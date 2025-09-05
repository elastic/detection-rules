# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Validation logic for rules containing queries."""

import re
import typing
from collections.abc import Callable
from enum import Enum
from functools import cached_property, wraps
from typing import Any

import click
import eql  # type: ignore[reportMissingTypeStubs]
import kql  # type: ignore[reportMissingTypeStubs]
from eql import ast  # type: ignore[reportMissingTypeStubs]
from eql.parser import KvTree, LarkToEQL, NodeInfo, TypeHint  # type: ignore[reportMissingTypeStubs]
from eql.parser import _parse as base_parse  # type: ignore[reportMissingTypeStubs]
from marshmallow import ValidationError
from semver import Version

from . import ecs, endgame
from .beats import get_datasets_and_modules
from .config import CUSTOM_RULES_DIR, load_current_package_version, parse_rules_config
from .custom_schemas import update_auto_generated_schema
from .integrations import get_integration_schema_data, load_integrations_manifests, parse_datasets
from .rule import EQLRuleData, QueryRuleData, QueryValidator, RuleMeta, TOMLRuleContents, set_eql_config
from .schemas import get_stack_schemas

EQL_ERROR_TYPES = (
    eql.EqlCompileError
    | eql.EqlError
    | eql.EqlParseError
    | eql.EqlSchemaError
    | eql.EqlSemanticError
    | eql.EqlSyntaxError
    | eql.EqlTypeMismatchError
)
KQL_ERROR_TYPES = kql.KqlCompileError | kql.KqlParseError
RULES_CONFIG = parse_rules_config()


class ExtendedTypeHint(Enum):
    IP = "ip"

    @classmethod
    def primitives(cls):  # noqa: ANN206
        """Get all primitive types."""
        return TypeHint.Boolean, TypeHint.Numeric, TypeHint.Null, TypeHint.String, ExtendedTypeHint.IP

    def is_primitive(self) -> bool:
        """Check if a type is a primitive."""
        return self in self.primitives()


@typing.no_type_check
def custom_in_set(self: LarkToEQL, node: KvTree) -> NodeInfo:
    """Override and address the limitations of the eql in_set method."""
    response = self.visit(node.child_trees)
    if not response:
        raise ValueError("Child trees are not provided")

    outer, container = response

    if not outer.validate_type(ExtendedTypeHint.primitives()):
        # can't compare non-primitives to sets
        raise self._type_error(outer, ExtendedTypeHint.primitives())

    # Check that everything inside the container has the same type as outside
    error_message = "Unable to compare {expected_type} to {actual_type}"
    for inner in container:
        if not inner.validate_type(outer):
            raise self._type_error(inner, outer, error_message)

    if self._elasticsearch_syntax and hasattr(outer, "type_info"):
        # Check edge case of in_set and ip/string comparison
        outer_type = outer.type_info
        if isinstance(self._schema, ecs.KqlSchema2Eql):
            type_hint = self._schema.kql_schema.get(str(outer.node), "unknown")
            if hasattr(self._schema, "type_mapping") and type_hint == "ip":
                outer.type_info = ExtendedTypeHint.IP
                for inner in container:
                    if not inner.validate_type(outer):
                        raise self._type_error(inner, outer, error_message)

        # reset the type
        outer.type_info = outer_type

    # This will always evaluate to true/false, so it should be a boolean
    term = ast.InSet(outer.node, [c.node for c in container])
    nullable = outer.nullable or any(c.nullable for c in container)
    return NodeInfo(term, TypeHint.Boolean, nullable=nullable, source=node)


def custom_base_parse_decorator(func: Callable[..., Any]) -> Callable[..., Any]:
    """Override and address the limitations of the eql in_set method."""

    @wraps(func)
    def wrapper(query: str, start: str | None = None, **kwargs: dict[str, Any]) -> Any:
        original_in_set = LarkToEQL.in_set  # type: ignore[reportUnknownMemberType]
        LarkToEQL.in_set = custom_in_set
        try:
            result = func(query, start=start, **kwargs)
        finally:  # Using finally to ensure that the original method is restored
            LarkToEQL.in_set = original_in_set
        return result

    return wrapper


eql.parser._parse = custom_base_parse_decorator(base_parse)  # type: ignore[reportPrivateUsage] # noqa: SLF001


class KQLValidator(QueryValidator):
    """Specific fields for KQL query event types."""

    @cached_property
    def ast(self) -> kql.ast.Expression:  # type: ignore[reportIncompatibleMethod]
        return kql.parse(self.query, normalize_kql_keywords=RULES_CONFIG.normalize_kql_keywords)  # type: ignore[reportUnknownMemberType]

    @cached_property
    def unique_fields(self) -> list[str]:  # type: ignore[reportIncompatibleMethod]
        return list({str(f) for f in self.ast if isinstance(f, kql.ast.Field)})  # type: ignore[reportUnknownVariableType]

    def auto_add_field(self, validation_checks_error: kql.errors.KqlParseError, index_or_dataview: str) -> None:
        """Auto add a missing field to the schema."""
        field_name = extract_error_field(self.query, validation_checks_error)
        if not field_name:
            raise ValueError("No fied name found for the error")
        field_type = ecs.get_all_flattened_schema().get(field_name)
        update_auto_generated_schema(index_or_dataview, field_name, field_type)

    def to_eql(self) -> eql.ast.Expression:
        return kql.to_eql(self.query)  # type: ignore[reportUnknownVariableType]

    def validate(self, data: QueryRuleData, meta: RuleMeta, max_attempts: int = 10) -> None:  # type: ignore[reportIncompatibleMethod]
        """Validate the query, called from the parent which contains [metadata] information."""
        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            # syntax only, which is done via self.ast
            return

        if data.language != "lucene":
            packages_manifest = load_integrations_manifests()
            package_integrations = TOMLRuleContents.get_packaged_integrations(data, meta, packages_manifest)

            for _ in range(max_attempts):
                if package_integrations:
                    # If we have integration information, validate against integrations only
                    exc = self.validate_integration(data, meta, package_integrations)
                    if exc is not None:
                        if (
                            isinstance(exc, eql.EqlParseError)
                            and "Field not recognized" in exc.error_msg
                            and RULES_CONFIG.auto_gen_schema_file
                        ):
                            # Auto add the field and re-validate
                            self.auto_add_field(exc, data.index_or_dataview[0])
                            continue
                        raise exc
                else:
                    # No integration information, fall back to stack validation
                    exc = self.validate_stack_combos(data, meta)
                    if exc is not None:
                        if "Field not recognized" in str(exc) and RULES_CONFIG.auto_gen_schema_file:
                            # Auto add the field and re-validate
                            self.auto_add_field(exc, data.index_or_dataview[0])  # type: ignore[reportArgumentType]
                            continue
                        raise exc

                # If we get here, validation passed
                break
            else:
                raise ValueError(f"Maximum validation attempts exceeded for {data.rule_id} - {data.name}")

    def validate_stack_combos(self, data: QueryRuleData, meta: RuleMeta) -> KQL_ERROR_TYPES | None:
        """Validate the query against ECS and beats schemas across stack combinations."""
        for stack_version, mapping in meta.get_validation_stack_versions().items():
            beats_version = mapping["beats"]
            ecs_version = mapping["ecs"]
            err_trailer = f"stack: {stack_version}, beats: {beats_version}, ecs: {ecs_version}"

            beat_types, _, schema = self.get_beats_schema(data.index_or_dataview, beats_version, ecs_version)

            try:
                kql.parse(self.query, schema=schema, normalize_kql_keywords=RULES_CONFIG.normalize_kql_keywords)  # type: ignore[reportUnknownMemberType]
            except kql.KqlParseError as exc:
                message = exc.error_msg
                trailer = err_trailer
                if "Unknown field" in message and beat_types:
                    trailer = f"\nTry adding event.module or data_stream.dataset to specify beats module\n\n{trailer}"

                return kql.KqlParseError(
                    exc.error_msg,  # type: ignore[reportUnknownArgumentType]
                    exc.line,  # type: ignore[reportUnknownArgumentType]
                    exc.column,  # type: ignore[reportUnknownArgumentType]
                    exc.source,  # type: ignore[reportUnknownArgumentType]
                    len(exc.caret.lstrip()),
                    trailer=trailer,
                )
        return None

    def validate_integration(  # noqa: PLR0912
        self,
        data: QueryRuleData,
        meta: RuleMeta,
        package_integrations: list[dict[str, Any]],
    ) -> KQL_ERROR_TYPES | None:
        """Validate the query, called from the parent which contains [metadata] information."""
        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            return None

        error_fields = {}
        package_schemas = {}

        # Initialize package_schemas with a nested structure
        for integration_data in package_integrations:
            package = integration_data["package"]
            integration = integration_data["integration"]
            if integration:
                package_schemas.setdefault(package, {}).setdefault(integration, {})  # type: ignore[reportUnknownMemberType]
            else:
                package_schemas.setdefault(package, {})  # type: ignore[reportUnknownMemberType]

        # Process each integration schema
        for integration_schema_data in get_integration_schema_data(data, meta, package_integrations):
            package, integration = (
                integration_schema_data["package"],
                integration_schema_data["integration"],
            )
            integration_schema = integration_schema_data["schema"]
            stack_version = integration_schema_data["stack_version"]

            # Add non-ecs-schema fields
            for index_name in data.index_or_dataview:
                integration_schema.update(**ecs.flatten(ecs.get_index_schema(index_name)))

            # Add custom schema fields for appropriate stack version
            if data.index and CUSTOM_RULES_DIR:
                for index_name in data.index_or_dataview:
                    integration_schema.update(**ecs.flatten(ecs.get_custom_index_schema(index_name, stack_version)))

            # Add endpoint schema fields for multi-line fields
            integration_schema.update(**ecs.flatten(ecs.get_endpoint_schemas()))
            if integration:
                package_schemas[package][integration] = integration_schema
            else:
                package_schemas[package] = integration_schema

            # Validate the query against the schema
            try:
                kql.parse(  # type: ignore[reportUnknownMemberType]
                    self.query,
                    schema=integration_schema,
                    normalize_kql_keywords=RULES_CONFIG.normalize_kql_keywords,
                )
            except kql.KqlParseError as exc:
                if exc.error_msg == "Unknown field":
                    field = extract_error_field(self.query, exc)
                    trailer = (
                        f"\n\tTry adding event.module or data_stream.dataset to specify integration module\n\t"
                        f"Will check against integrations {meta.integration} combined.\n\t"
                        f"{package=}, {integration=}, {integration_schema_data['package_version']=}, "
                        f"{integration_schema_data['stack_version']=}, "
                        f"{integration_schema_data['ecs_version']=}"
                    )
                    error_fields[field] = {
                        "error": exc,
                        "trailer": trailer,
                        "package": package,
                        "integration": integration,
                    }
                    if data.get("notify", False):
                        print(f"\nWarning: `{field}` in `{data.name}` not found in schema. {trailer}")
                else:
                    return kql.KqlParseError(
                        exc.error_msg,  # type: ignore[reportUnknownArgumentType]
                        exc.line,  # type: ignore[reportUnknownArgumentType]
                        exc.column,  # type: ignore[reportUnknownArgumentType]
                        exc.source,  # type: ignore[reportUnknownArgumentType]
                        len(exc.caret.lstrip()),
                        exc.trailer,  # type: ignore[reportUnknownArgumentType]
                    )

        # Check error fields against schemas of different packages or different integrations
        for field, error_data in list(error_fields.items()):  # type: ignore[reportUnknownArgumentType]
            error_package, error_integration = (  # type: ignore[reportUnknownVariableType]
                error_data["package"],
                error_data["integration"],
            )
            for package, integrations_or_schema in package_schemas.items():  # type: ignore[reportUnknownVariableType]
                if error_integration is None:
                    # Compare against the schema directly if there's no integration
                    if error_package != package and field in integrations_or_schema:
                        del error_fields[field]
                        break
                else:
                    # Compare against integration schemas
                    for integration, schema in integrations_or_schema.items():  # type: ignore[reportUnknownMemberType]
                        check_alt_schema = error_package != package or (  # type: ignore[reportUnknownVariableType]
                            error_package == package and error_integration != integration
                        )
                        if check_alt_schema and field in schema:
                            del error_fields[field]

        # Raise the first error
        if error_fields:
            _, error_data = next(iter(error_fields.items()))  # type: ignore[reportUnknownVariableType]
            return kql.KqlParseError(
                error_data["error"].error_msg,  # type: ignore[reportUnknownArgumentType]
                error_data["error"].line,  # type: ignore[reportUnknownArgumentType]
                error_data["error"].column,  # type: ignore[reportUnknownArgumentType]
                error_data["error"].source,  # type: ignore[reportUnknownArgumentType]
                len(error_data["error"].caret.lstrip()),  # type: ignore[reportUnknownArgumentType]
                error_data["trailer"],  # type: ignore[reportUnknownArgumentType]
            )
        return None


class EQLValidator(QueryValidator):
    """Specific fields for EQL query event types."""

    @cached_property
    def ast(self) -> eql.ast.Expression:  # type: ignore[reportIncompatibleMethodOverrichemas]
        latest_version = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
        cfg = set_eql_config(str(latest_version))
        with eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions, eql.parser.skip_optimizations, cfg:
            return eql.parse_query(self.query)  # type: ignore[reportUnknownVariableType]

    def text_fields(self, eql_schema: ecs.KqlSchema2Eql | endgame.EndgameSchema) -> list[str]:
        """Return a list of fields of type text."""
        from kql.parser import elasticsearch_type_family  # type: ignore[reportMissingTypeStubs]

        schema = eql_schema.kql_schema if isinstance(eql_schema, ecs.KqlSchema2Eql) else eql_schema.endgame_schema

        return [f for f in self.unique_fields if elasticsearch_type_family(schema.get(f)) == "text"]  # type: ignore[reportArgumentType]

    @cached_property
    def unique_fields(self) -> list[str]:  # type: ignore[reportIncompatibleMethodOverride]
        return list({str(f) for f in self.ast if isinstance(f, eql.ast.Field)})  # type: ignore[reportUnknownVariableType]

    def auto_add_field(self, validation_checks_error: eql.errors.EqlParseError, index_or_dataview: str) -> None:
        """Auto add a missing field to the schema."""
        field_name = extract_error_field(self.query, validation_checks_error)
        if not field_name:
            raise ValueError("No field name found")
        field_type = ecs.get_all_flattened_schema().get(field_name)
        update_auto_generated_schema(index_or_dataview, field_name, field_type)

    def validate(self, data: "QueryRuleData", meta: RuleMeta, max_attempts: int = 10) -> None:  # type: ignore[reportIncompatibleMethodOverride]  # noqa: PLR0912
        """Validate an EQL query while checking TOMLRule."""
        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            # syntax only, which is done via self.ast
            return

        if data.language != "lucene":
            packages_manifest = load_integrations_manifests()
            package_integrations = TOMLRuleContents.get_packaged_integrations(data, meta, packages_manifest)

            # Decide sequence vs non-sequence using rule-provided flag
            is_sequence = data.is_sequence  # type: ignore[reportAttributeAccessIssue]

            for _ in range(max_attempts):
                stack_check = None
                integrations_check = None

                # Choose the appropriate validation path
                if is_sequence:
                    # For sequences, validate per-subquery integrations and also run a stack pass for trace context
                    if package_integrations:
                        integrations_check = self.validate_integration(data, meta, package_integrations)  # type: ignore[reportArgumentType]
                    else:
                        integrations_check = self.validate_integration(data, meta, [])  # type: ignore[reportArgumentType]
                    stack_check = self.validate_stack_combos(data, meta)  # type: ignore[reportArgumentType]
                elif package_integrations:
                    # Non-sequence: validate against either integrations OR stack combos (not both)
                    integrations_check = self.validate_integration(data, meta, package_integrations)  # type: ignore[reportArgumentType]
                else:
                    stack_check = self.validate_stack_combos(data, meta)  # type: ignore[reportArgumentType]

                # Handle results
                if is_sequence:
                    if integrations_check:
                        # If auto-add is enabled and stack shows unrecognized field, try auto-add, then retry
                        if (
                            stack_check
                            and RULES_CONFIG.auto_gen_schema_file
                            and ("Field not recognized" in str(stack_check))
                        ):
                            self.auto_add_field(stack_check, data.index_or_dataview[0])  # type: ignore[reportArgumentType]
                            continue

                        if stack_check:
                            click.echo(f"Stack Error Trace: {stack_check}")
                            click.echo(f"Integrations Error Trace: {integrations_check}")
                        # Combined error for sequences to match unit test expectations
                        raise ValueError("Error in both stack and integrations checks")

                    # No integrations error - if stack-only errored and no integrations present, handle/raise
                    if stack_check and not package_integrations:
                        if "Field not recognized" in str(stack_check) and RULES_CONFIG.auto_gen_schema_file:
                            self.auto_add_field(stack_check, data.index_or_dataview[0])  # type: ignore[reportArgumentType]
                            continue
                        raise stack_check
                else:
                    # Non-sequence flow
                    if integrations_check:
                        raise integrations_check

                    if stack_check:
                        if "Field not recognized" in str(stack_check) and RULES_CONFIG.auto_gen_schema_file:
                            self.auto_add_field(stack_check, data.index_or_dataview[0])  # type: ignore[reportArgumentType]
                            continue
                        raise stack_check

                # Success
                break

            else:
                raise ValueError(f"Maximum validation attempts exceeded for {data.rule_id} - {data.name}")

            rule_type_config_fields, rule_type_config_validation_failed = self.validate_rule_type_configurations(
                data,  # type: ignore[reportArgumentType]
                meta,
            )
            if rule_type_config_validation_failed:
                raise ValueError(
                    f"""Rule type config values are not ECS compliant, check these values:
                                {rule_type_config_fields}"""
                )

    def validate_stack_combos(self, data: QueryRuleData, meta: RuleMeta) -> EQL_ERROR_TYPES | None | ValueError:
        """Validate the query against ECS and beats schemas across stack combinations."""
        for stack_version, mapping in meta.get_validation_stack_versions().items():
            beats_version = mapping["beats"]
            ecs_version = mapping["ecs"]
            endgame_version = mapping["endgame"]
            err_trailer = (
                f"stack: {stack_version}, beats: {beats_version},ecs: {ecs_version}, endgame: {endgame_version}"
            )

            beat_types, _, schema = self.get_beats_schema(data.index_or_dataview, beats_version, ecs_version)
            endgame_schema = self.get_endgame_schema(data.index_or_dataview, endgame_version)
            eql_schema = ecs.KqlSchema2Eql(schema)

            # validate query against the beats and eql schema
            exc = self.validate_query_with_schema(  # type: ignore[reportUnknownVariableType]
                data=data,
                schema=eql_schema,
                err_trailer=err_trailer,
                beat_types=beat_types,
                min_stack_version=meta.min_stack_version,  # type: ignore[reportArgumentType]
            )
            if exc:
                return exc

            if endgame_schema:
                # validate query against the endgame schema
                exc = self.validate_query_with_schema(
                    data=data,
                    schema=endgame_schema,
                    err_trailer=err_trailer,
                    min_stack_version=meta.min_stack_version,  # type: ignore[reportArgumentType]
                )
                if exc:
                    raise exc
        return None

    def validate_integration(  # noqa: PLR0912, PLR0915, PLR0911
        self,
        data: QueryRuleData,
        meta: RuleMeta,
        package_integrations: list[dict[str, Any]],
    ) -> EQL_ERROR_TYPES | None | ValueError:
        """Validate an EQL query while checking TOMLRule against integration schemas.

        If the EQL query is a sequence, validate each subquery against the schema of the dataset's
        integration.package referenced within that subquery. This avoids cross-integration field
        mismatches when multiple datasets from the same integration are used in different subqueries.
        """
        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            return None

        def _prepare_integration_schema(schema_dict: dict[str, Any], stack_version: str) -> dict[str, Any]:
            """Add index/custom/endpoint fields to the base integration schema."""
            if data.index_or_dataview:
                for index_name in data.index_or_dataview:  # type: ignore[reportArgumentType]
                    schema_dict.update(**ecs.flatten(ecs.get_index_schema(index_name)))

            if data.index_or_dataview and CUSTOM_RULES_DIR:
                for index_name in data.index_or_dataview:
                    schema_dict.update(**ecs.flatten(ecs.get_custom_index_schema(index_name, stack_version)))

            schema_dict.update(**ecs.flatten(ecs.get_endpoint_schemas()))
            return schema_dict

        def _build_integration_err_trailer(
            context: str,
            packages_str: str,
            stack_version: str,
            ecs_version: str,
        ) -> str:
            """Build a clean, readable error trailer for integration validation."""
            hint = (
                "Try adding event.module or event.dataset to specify integration module"
                if "event.module or event.dataset" in context
                else context
            ).strip()
            prefix = f"{hint}\n" if hint else ""
            return f"{prefix}Checked against packages [{packages_str}]; stack: {stack_version}; ecs: {ecs_version}"

        def _validate_query_against_integrations(
            query_text: str,
            packaged_integrations: list[dict[str, Any]],
            context: str,
            *,
            accumulate_by_stack: bool = True,
        ) -> EQL_ERROR_TYPES | ValueError | None:
            """Validate a query text against packaged integrations. When accumulate_by_stack is True (default),
            union schemas per stack version and validate once per stack. Otherwise, validate against each integration
            individually (used for per-subquery sequence checks).
            """
            if accumulate_by_stack:
                combined_by_stack: dict[str, dict[str, Any]] = {}
                ecs_by_stack: dict[str, str] = {}
                packages_by_stack: dict[str, set[str]] = {}

                for integration_schema_data in get_integration_schema_data(data, meta, packaged_integrations):
                    stack_version = integration_schema_data["stack_version"]
                    ecs_version = integration_schema_data["ecs_version"]
                    package = integration_schema_data["package"]
                    integration_schema = integration_schema_data["schema"]

                    prepared = _prepare_integration_schema(integration_schema, stack_version)
                    _ = ecs_by_stack.setdefault(stack_version, ecs_version)
                    packages_by_stack.setdefault(stack_version, set()).add(package)
                    combined_by_stack.setdefault(stack_version, {}).update(prepared)

                for stack_version, schema_dict in combined_by_stack.items():
                    ecs_version = ecs_by_stack.get(stack_version, "unknown")
                    pkgs = ", ".join(sorted(packages_by_stack.get(stack_version, set())))
                    err_trailer = _build_integration_err_trailer(context, pkgs, stack_version, ecs_version)

                    exc = self.validate_query_text_with_schema(
                        query_text,
                        ecs.KqlSchema2Eql(schema_dict),
                        err_trailer=err_trailer,
                        min_stack_version=meta.min_stack_version,  # type: ignore[reportArgumentType]
                    )
                    if exc is not None:
                        return exc
                return None

            # Validate each integration combination individually
            for integration_schema_data in get_integration_schema_data(data, meta, packaged_integrations):
                package = integration_schema_data["package"]
                package_version = integration_schema_data["package_version"]
                integration_schema = integration_schema_data["schema"]
                stack_version = integration_schema_data["stack_version"]
                ecs_version = integration_schema_data["ecs_version"]

                # Prepare schema with additional fields
                integration_schema = _prepare_integration_schema(integration_schema, stack_version)

                # Build error trailer for context
                err_trailer = (
                    f"{context}. package: {package}, package_version: {package_version}, "
                    f"stack: {stack_version}, ecs: {ecs_version}"
                )

                exc = self.validate_query_text_with_schema(
                    query_text,
                    ecs.KqlSchema2Eql(integration_schema),
                    err_trailer=err_trailer,
                    min_stack_version=meta.min_stack_version,  # type: ignore[reportArgumentType]
                )
                if exc is not None:
                    return exc
            return None

        def _validate_subquery_against_stack(subquery: "ast.SubqueryBy") -> EQL_ERROR_TYPES | ValueError | None:
            """Validate a subquery against stack schemas (ECS/beats) when no integration data is available."""
            synthetic_sequence = _build_synthetic_sequence_from_subquery(subquery)

            # Create a temporary validator for the synthetic sequence
            temp_validator = EQLValidator(synthetic_sequence)

            # Use the existing stack validation logic
            return temp_validator.validate_stack_combos(data, meta)  # type: ignore[reportArgumentType]

        def _build_synthetic_sequence_from_subquery(subquery: "ast.SubqueryBy") -> str:
            """Build a minimal synthetic sequence containing the subquery for validation."""
            subquery_text = str(subquery)
            join_fields = ", ".join(map(str, getattr(subquery, "join_values", []) or []))
            dummy_by = f" by {join_fields}" if join_fields else ""
            return f"sequence\n  {subquery_text}\n  [any where true]{dummy_by}"

        # Handle sequence queries with per-subquery validation
        if data.is_sequence:  # type: ignore[reportAttributeAccessIssue]
            sequence: ast.Sequence = self.ast.first  # type: ignore[reportAttributeAccessIssue]
            packages_manifest = load_integrations_manifests()
            subqueries_validated = 0

            for subquery in sequence.queries:  # type: ignore[reportUnknownVariableType]
                subquery_validated = False

                # Get datasets used in this specific subquery
                subquery_datasets, _ = get_datasets_and_modules(subquery)  # type: ignore[reportUnknownVariableType]

                if subquery_datasets:
                    # Build subquery-specific package integrations from datasets
                    subquery_pkg_ints = parse_datasets(list(subquery_datasets), packages_manifest)

                    if subquery_pkg_ints:
                        # Validate the subquery with its specific integration schemas
                        synthetic_sequence = _build_synthetic_sequence_from_subquery(subquery)  # type: ignore[reportUnknownVariableType]
                        exc = _validate_query_against_integrations(
                            synthetic_sequence,
                            subquery_pkg_ints,
                            "Subquery schema mismatch",
                            accumulate_by_stack=False,
                        )
                        if exc is not None:
                            return exc
                        subquery_validated = True

                # If subquery wasn't validated via dataset, check metadata integrations or fall back to stack
                if not subquery_validated:
                    # Build metadata-based package list for datasetless subquery
                    meta_integrations = meta.integration
                    if isinstance(meta_integrations, str):
                        meta_integrations = [meta_integrations]
                    elif meta_integrations is None:
                        meta_integrations = []

                    meta_pkg_ints = [
                        {"package": pkg, "integration": None} for pkg in meta_integrations if pkg in packages_manifest
                    ]

                    if meta_pkg_ints:
                        # Validate datasetless subquery against union of metadata integrations per stack
                        synthetic_sequence = _build_synthetic_sequence_from_subquery(subquery)  # type: ignore[reportUnknownVariableType]
                        exc = _validate_query_against_integrations(
                            synthetic_sequence,
                            meta_pkg_ints,
                            "Datasetless subquery validation against metadata integrations",
                            accumulate_by_stack=True,
                        )
                        if exc is not None:
                            return exc
                        subquery_validated = True
                    else:
                        # No integration metadata - validate against stack schemas
                        exc = _validate_subquery_against_stack(subquery)  # type: ignore[reportUnknownVariableType]
                        if exc is not None:
                            return exc
                        subquery_validated = True

                if subquery_validated:
                    subqueries_validated += 1

            # If no subqueries were validated individually, validate the full query
            if subqueries_validated == 0:
                exc = _validate_query_against_integrations(
                    self.query,
                    package_integrations,
                    "Try adding event.module or event.dataset to specify integration module",
                    accumulate_by_stack=True,
                )
                if exc is not None:
                    return exc
        else:
            # Non-sequence query: validate against all package integrations
            exc = _validate_query_against_integrations(
                self.query,
                package_integrations,
                "Try adding event.module or event.dataset to specify integration module",
                accumulate_by_stack=True,
            )
            if exc is not None:
                return exc

        return None

    def validate_query_with_schema(
        self,
        data: "QueryRuleData",  # noqa: ARG002
        schema: ecs.KqlSchema2Eql | endgame.EndgameSchema,
        err_trailer: str,
        min_stack_version: str,
        beat_types: list[str] | None = None,
    ) -> EQL_ERROR_TYPES | ValueError | None:
        """Validate the query against the schema (delegates to validate_query_text_with_schema)."""
        return self.validate_query_text_with_schema(
            self.query,
            schema,
            err_trailer=err_trailer,
            min_stack_version=min_stack_version,
            beat_types=beat_types,
        )

    def validate_query_text_with_schema(
        self,
        query_text: str,
        schema: ecs.KqlSchema2Eql | endgame.EndgameSchema,
        err_trailer: str,
        min_stack_version: str,
        beat_types: list[str] | None = None,
    ) -> EQL_ERROR_TYPES | ValueError | None:
        """Validate the provided EQL query text against the schema (variant of validate_query_with_schema)."""
        try:
            config = set_eql_config(min_stack_version)
            with config, schema, eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
                _ = eql.parse_query(query_text)  # type: ignore[reportUnknownMemberType]
        except eql.EqlParseError as exc:
            message = exc.error_msg
            trailer = err_trailer
            if "Unknown field" in message and beat_types:
                trailer = f"\nTry adding event.module or event.dataset to specify beats module\n\n{trailer}"
            elif "Field not recognized" in message and isinstance(schema, ecs.KqlSchema2Eql):
                text_fields = self.text_fields(schema)
                if text_fields:
                    fields_str = ", ".join(text_fields)
                    trailer = f"\neql does not support text fields: {fields_str}\n\n{trailer}"

            return exc.__class__(
                exc.error_msg,  # type: ignore[reportUnknownArgumentType]
                exc.line,  # type: ignore[reportUnknownArgumentType]
                exc.column,  # type: ignore[reportUnknownArgumentType]
                exc.source,  # type: ignore[reportUnknownArgumentType]
                len(exc.caret.lstrip()),
                trailer=trailer,
            )
        except Exception as exc:  # noqa: BLE001
            print(err_trailer)
            return exc  # type: ignore[reportReturnType]

    def validate_rule_type_configurations(self, data: EQLRuleData, meta: RuleMeta) -> tuple[list[str | None], bool]:
        """Validate EQL rule type configurations."""
        if data.timestamp_field or data.event_category_override or data.tiebreaker_field:
            # Get a list of rule type configuration fields
            fields = ["timestamp_field", "event_category_override", "tiebreaker_field"]
            set_fields = list(filter(None, (data.get(field) for field in fields)))  # type: ignore[reportUnknownVariableType]

            # get stack_version and ECS schema
            min_stack_version = meta.get("min_stack_version")
            if min_stack_version is None:
                min_stack_version = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
            ecs_version = get_stack_schemas()[str(min_stack_version)]["ecs"]
            schema = ecs.get_schema(ecs_version)

            # return a list of rule type config field values and whether any are not in the schema
            return (set_fields, any(f not in schema for f in set_fields))  # type: ignore[reportUnknownVariableType]
        # if rule type fields are not set, return an empty list and False
        return [], False


class ESQLValidator(QueryValidator):
    """Validate specific fields for ESQL query event types."""

    @cached_property
    def ast(self) -> None:  # type: ignore[reportIncompatibleMethodOverride]
        return None

    @cached_property
    def unique_fields(self) -> list[str]:  # type: ignore[reportIncompatibleMethodOverride]
        """Return a list of unique fields in the query."""
        # return empty list for ES|QL rules until ast is available (friendlier than raising error)
        return []

    def validate(self, _: "QueryRuleData", __: RuleMeta) -> None:  # type: ignore[reportIncompatibleMethodOverride]
        """Validate an ESQL query while checking TOMLRule."""
        # temporarily override to NOP until ES|QL query parsing is supported

    def validate_integration(
        self,
        _: QueryRuleData,
        __: RuleMeta,
        ___: list[dict[str, Any]],
    ) -> ValidationError | None | ValueError:
        # Disabling self.validate(data, meta)
        pass


def extract_error_field(source: str, exc: eql.EqlParseError | kql.KqlParseError) -> str | None:
    """Extract the field name from an EQL or KQL parse error."""
    lines = source.splitlines()
    mod = -1 if exc.line == len(lines) else 0  # type: ignore[reportUnknownMemberType]
    line = lines[exc.line + mod]  # type: ignore[reportUnknownMemberType]
    start = exc.column  # type: ignore[reportUnknownMemberType]
    stop = start + len(exc.caret.strip())  # type: ignore[reportUnknownVariableType]
    return re.sub(r"^\W+|\W+$", "", line[start:stop])  # type: ignore[reportUnknownArgumentType]

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Validation logic for rules containing queries."""

import re
import time
import typing
from collections.abc import Callable
from enum import Enum
from functools import cached_property, wraps
from typing import Any

import click
import eql  # type: ignore[reportMissingTypeStubs]
import kql  # type: ignore[reportMissingTypeStubs]
from elasticsearch import Elasticsearch  # type: ignore[reportMissingTypeStubs]
from eql import ast  # type: ignore[reportMissingTypeStubs]
from eql.parser import KvTree, LarkToEQL, NodeInfo, TypeHint  # type: ignore[reportMissingTypeStubs]
from eql.parser import _parse as base_parse  # type: ignore[reportMissingTypeStubs]
from kibana import Kibana  # type: ignore[reportMissingTypeStubs]
from marshmallow import ValidationError
from semver import Version

from . import ecs, endgame, integrations, misc, utils
from .config import CUSTOM_RULES_DIR, load_current_package_version, parse_rules_config
from .custom_schemas import update_auto_generated_schema
from .integrations import get_integration_schema_data, load_integrations_manifests, load_integrations_schemas
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
        raise self._type_error(outer, ExtendedTypeHint.primit())

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
                validation_checks: dict[str, KQL_ERROR_TYPES | None] = {"stack": None, "integrations": None}
                # validate the query against fields within beats
                validation_checks["stack"] = self.validate_stack_combos(data, meta)

                if package_integrations:
                    # validate the query against related integration fields
                    validation_checks["integrations"] = self.validate_integration(data, meta, package_integrations)

                if validation_checks["stack"] and not package_integrations:
                    # if auto add, try auto adding and then call stack_combo validation again
                    if validation_checks["stack"].error_msg == "Unknown field" and RULES_CONFIG.auto_gen_schema_file:  # type: ignore[reportAttributeAccessIssue]
                        # auto add the field and re-validate
                        self.auto_add_field(validation_checks["stack"], data.index_or_dataview[0])  # type: ignore[reportArgumentType]
                    else:
                        raise validation_checks["stack"]

                if validation_checks["stack"] and validation_checks["integrations"]:
                    # if auto add, try auto adding and then call stack_combo validation again
                    if validation_checks["stack"].error_msg == "Unknown field" and RULES_CONFIG.auto_gen_schema_file:  # type: ignore[reportAttributeAccessIssue]
                        # auto add the field and re-validate
                        self.auto_add_field(validation_checks["stack"], data.index_or_dataview[0])  # type: ignore[reportArgumentType]
                    else:
                        click.echo(f"Stack Error Trace: {validation_checks['stack']}")
                        click.echo(f"Integrations Error Trace: {validation_checks['integrations']}")
                        raise ValueError("Error in both stack and integrations checks")

                else:
                    break

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

            for _ in range(max_attempts):
                validation_checks = {"stack": None, "integrations": None}
                # validate the query against fields within beats
                validation_checks["stack"] = self.validate_stack_combos(data, meta)  # type: ignore[reportArgumentType]

                stack_check = validation_checks["stack"]

                if package_integrations:
                    # validate the query against related integration fields
                    validation_checks["integrations"] = self.validate_integration(data, meta, package_integrations)  # type: ignore[reportArgumentType]

                if stack_check and not package_integrations:
                    # if auto add, try auto adding and then validate again
                    if (
                        "Field not recognized" in str(stack_check)  # type: ignore[reportUnknownMemberType]
                        and RULES_CONFIG.auto_gen_schema_file
                    ):
                        # auto add the field and re-validate
                        self.auto_add_field(stack_check, data.index_or_dataview[0])  # type: ignore[reportArgumentType]
                    else:
                        raise stack_check

                elif stack_check and validation_checks["integrations"]:
                    # if auto add, try auto adding and then validate again
                    if (
                        "Field not recognized" in stack_check.error_msg  # type: ignore[reportUnknownMemberType]
                        and RULES_CONFIG.auto_gen_schema_file
                    ):
                        # auto add the field and re-validate
                        self.auto_add_field(stack_check, data.index_or_dataview[0])  # type: ignore[reportArgumentType]
                    else:
                        click.echo(f"Stack Error Trace: {stack_check}")
                        click.echo(f"Integrations Error Trace: {validation_checks['integrations']}")
                        raise ValueError("Error in both stack and integrations checks")

                else:
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

    def validate_integration(  # noqa: PLR0912
        self,
        data: QueryRuleData,
        meta: RuleMeta,
        package_integrations: list[dict[str, Any]],
    ) -> EQL_ERROR_TYPES | None | ValueError:
        """Validate an EQL query while checking TOMLRule against integration schemas."""
        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            # syntax only, which is done via self.ast
            return None

        error_fields = {}
        package_schemas: dict[str, Any] = {}

        # Initialize package_schemas with a nested structure
        for integration_data in package_integrations:
            package = integration_data["package"]
            integration = integration_data["integration"]
            if integration:
                package_schemas.setdefault(package, {}).setdefault(integration, {})
            else:
                package_schemas.setdefault(package, {})

        # Process each integration schema
        for integration_schema_data in get_integration_schema_data(data, meta, package_integrations):
            ecs_version = integration_schema_data["ecs_version"]
            package, integration = (
                integration_schema_data["package"],
                integration_schema_data["integration"],
            )
            package_version = integration_schema_data["package_version"]
            integration_schema = integration_schema_data["schema"]
            stack_version = integration_schema_data["stack_version"]

            # add non-ecs-schema fields for edge cases not added to the integration
            if data.index_or_dataview:
                for index_name in data.index_or_dataview:
                    integration_schema.update(**ecs.flatten(ecs.get_index_schema(index_name)))

            # Add custom schema fields for appropriate stack version
            if data.index_or_dataview and CUSTOM_RULES_DIR:
                for index_name in data.index_or_dataview:
                    integration_schema.update(**ecs.flatten(ecs.get_custom_index_schema(index_name, stack_version)))

            # add endpoint schema fields for multi-line fields
            integration_schema.update(**ecs.flatten(ecs.get_endpoint_schemas()))
            package_schemas[package].update(**integration_schema)

            eql_schema = ecs.KqlSchema2Eql(integration_schema)
            err_trailer = (
                f"stack: {stack_version}, integration: {integration},"
                f"ecs: {ecs_version}, package: {package}, package_version: {package_version}"
            )

            # Validate the query against the schema
            exc = self.validate_query_with_schema(
                data=data,
                schema=eql_schema,
                err_trailer=err_trailer,
                min_stack_version=meta.min_stack_version,  # type: ignore[reportArgumentType]
            )

            if isinstance(exc, eql.EqlParseError):
                message = exc.error_msg  # type: ignore[reportUnknownVariableType]
                if message == "Unknown field" or "Field not recognized" in message:
                    field = extract_error_field(self.query, exc)
                    trailer = (
                        f"\n\tTry adding event.module or data_stream.dataset to specify integration module\n\t"
                        f"Will check against integrations {meta.integration} combined.\n\t"
                        f"{package=}, {integration=}, {package_version=}, "
                        f"{stack_version=}, {ecs_version=}"
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
                    return exc

        # Check error fields against schemas of different packages or different integrations
        for field, error_data in list(error_fields.items()):  # type: ignore[reportUnknownArgumentType]
            error_package, error_integration = (  # type: ignore[reportUnknownVariableType]
                error_data["package"],
                error_data["integration"],
            )
            for package, integrations_or_schema in package_schemas.items():
                if error_integration is None:
                    # Compare against the schema directly if there's no integration
                    if error_package != package and field in integrations_or_schema:
                        del error_fields[field]
                else:
                    # Compare against integration schemas
                    for integration, schema in integrations_or_schema.items():
                        check_alt_schema = (  # type: ignore[reportUnknownVariableType]
                            error_package != package or (error_package == package and error_integration != integration)
                        )
                        if check_alt_schema and field in schema:
                            del error_fields[field]

        # raise the first error
        if error_fields:
            _, data = next(iter(error_fields.items()))  # type: ignore[reportUnknownArgumentType]
            return data["error"]  # type: ignore[reportIndexIssue]
        return None

    def validate_query_with_schema(
        self,
        data: "QueryRuleData",  # noqa: ARG002
        schema: ecs.KqlSchema2Eql | endgame.EndgameSchema,
        err_trailer: str,
        min_stack_version: str,
        beat_types: list[str] | None = None,
    ) -> EQL_ERROR_TYPES | ValueError | None:
        """Validate the query against the schema."""
        try:
            config = set_eql_config(min_stack_version)
            with config, schema, eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
                _ = eql.parse_query(self.query)  # type: ignore[reportUnknownMemberType]
        except eql.EqlParseError as exc:
            message = exc.error_msg
            trailer = err_trailer
            if "Unknown field" in message and beat_types:
                trailer = f"\nTry adding event.module or data_stream.dataset to specify beats module\n\n{trailer}"
            elif "Field not recognized" in message:
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
            # get a list of rule type configuration fields
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
        # TODO
        # temporarily override to NOP until ES|QL query parsing is supported
        # if ENV VAR :
        #     self.remote_validate_rule
        # else:
        #     ESQLRuleData validation

    # NOTE will go away
    def validate_integration(
        self,
        _: QueryRuleData,
        __: RuleMeta,
        ___: list[dict[str, Any]],
    ) -> ValidationError | None | ValueError:
        # Disabling self.validate(data, meta)
        pass

    def get_rule_integrations(self, contents: TOMLRuleContents) -> list[str]:
        """Retrieve rule integrations from metadata."""
        rule_integrations: list[str] = []
        if contents.metadata.integration:
            if isinstance(contents.metadata.integration, list):
                rule_integrations = contents.metadata.integration
            else:
                rule_integrations = [contents.metadata.integration]
        return rule_integrations

    def prepare_integration_mappings(
        self,
        rule_integrations: list[str],
        stack_version: str,
        package_manifests: Any,
        integration_schemas: Any,
        log: Callable[[str], None],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Prepare integration mappings for the given rule integrations."""
        integration_mappings: dict[str, Any] = {}
        index_lookup: dict[str, Any] = {}
        for integration in rule_integrations:
            package = integration
            package_version, _ = integrations.find_latest_compatible_version(
                package,
                "",
                Version.parse(stack_version),
                package_manifests,
            )
            package_schema = integration_schemas[package][package_version]

            for stream in package_schema:
                flat_schema = package_schema[stream]
                stream_mappings = utils.flat_schema_to_index_mapping(flat_schema)
                nested_multifields = self.find_nested_multifields(stream_mappings)
                for field in nested_multifields:
                    field_name = str(field).split(".fields.")[0].replace(".", ".properties.") + ".fields"
                    log(
                        f"Warning: Nested multi-field `{field}` found in `{integration}-{stream}`. "
                        f"Removing parent field from schema for ES|QL validation."
                    )
                    utils.delete_nested_key_from_dict(stream_mappings, field_name)
                utils.combine_dicts(integration_mappings, stream_mappings)
                index_lookup[f"{integration}-{stream}"] = stream_mappings

        return integration_mappings, index_lookup

    def validate_columns_index_mapping(
        self, query_columns: list[dict[str, str]], combined_mappings: dict[str, Any]
    ) -> bool:
        """Validate that the columns in the ESQL query match the provided mappings."""
        mismatched_columns: list[str] = []

        for column in query_columns:
            column_name = column["name"]
            # Skip Dynamic fields
            if column_name.startswith(("Esql.", "Esql_priv.")):
                continue
            # Skip internal fields
            if column_name in ("_id", "_version", "_index"):
                continue
            column_type = column["type"]

            # Check if the column exists in combined_mappings or a valid field generated from a function or operator
            keys = column_name.split(".")
            schema_type = utils.get_column_from_index_mapping_schema(keys, combined_mappings)

            # Validate the type
            if not schema_type or column_type != schema_type:
                mismatched_columns.append(
                    f"Dynamic field `{column_name}` is not correctly mapped. "
                    f"If not dynamic: expected `{schema_type}`, got `{column_type}`."
                )

        if mismatched_columns:
            raise ValueError("Column validation errors:\n" + "\n".join(mismatched_columns))

        return True

    def create_remote_indices(
        self,
        elastic_client: Elasticsearch,
        existing_mappings: dict[str, Any],
        index_lookup: dict[str, Any],
        log: Callable[[str], None],
    ) -> str:
        """Create remote indices for validation and return the index string."""
        suffix = str(int(time.time() * 1000))
        test_index = f"rule-test-index-{suffix}"
        response = misc.create_index_with_index_mapping(elastic_client, test_index, existing_mappings)
        log(f"Index `{test_index}` created: {response}")
        full_index_str = test_index

        # create all integration indices
        for index, properties in index_lookup.items():
            ind_index_str = f"test-{index.rstrip('*')}{suffix}"
            response = misc.create_index_with_index_mapping(elastic_client, ind_index_str, properties)
            log(f"Index `{ind_index_str}` created: {response}")
            full_index_str = f"{full_index_str}, {ind_index_str}"

        return full_index_str

    def execute_query_against_indices(
        self,
        elastic_client: Elasticsearch,
        query: str,
        test_index_str: str,
        log: Callable[[str], None],
        delete_indices: bool = True,
    ) -> list[Any]:
        """Execute the ESQL query against the test indices on a remote Stack and return the columns."""
        try:
            log(f"Executing a query against `{test_index_str}`")
            response = elastic_client.esql.query(query=query)
            log(f"Got query response: {response}")
            query_columns = response.get("columns", [])
        finally:
            if delete_indices:
                for index_str in test_index_str.split(","):
                    response = elastic_client.indices.delete(index=index_str.strip())
                    log(f"Test index `{index_str}` deleted: {response}")

        query_column_names = [c["name"] for c in query_columns]
        log(f"Got query columns: {', '.join(query_column_names)}")
        return query_columns

    def find_nested_multifields(self, mapping: dict[str, Any], path: str = "") -> list[Any]:
        """Recursively search for nested multi-fields in Elasticsearch mappings."""
        nested_multifields = []

        for field, properties in mapping.items():
            current_path = f"{path}.{field}" if path else field

            if isinstance(properties, dict):
                # Check if the field has a `fields` key
                if "fields" in properties:
                    # Check if any subfield in `fields` also has a `fields` key
                    for subfield, subproperties in properties["fields"].items():  # type: ignore[reportUnknownVariableType]
                        if isinstance(subproperties, dict) and "fields" in subproperties:
                            nested_multifields.append(f"{current_path}.fields.{subfield}")  # type: ignore[reportUnknownVariableType]

                # Recurse into subfields
                if "properties" in properties:
                    nested_multifields.extend(  # type: ignore[reportUnknownVariableType]
                        self.find_nested_multifields(properties["properties"], current_path)  # type: ignore[reportUnknownVariableType]
                    )

        return nested_multifields  # type: ignore[reportUnknownVariableType]

    def get_ecs_schema_mappings(self, current_version: Version) -> dict[str, Any]:
        """Get the ECS schema in an index mapping format (nested schema) handling scaled floats."""
        ecs_version = get_stack_schemas()[str(current_version)]["ecs"]
        ecs_schemas = ecs.get_schemas()
        ecs_schema_flattened: dict[str, Any] = {}
        ecs_schema_scaled_floats: dict[str, Any] = {}
        for index, info in ecs_schemas[ecs_version]["ecs_flat"].items():
            if info["type"] == "scaled_float":
                ecs_schema_scaled_floats.update({index: info["scaling_factor"]})
            ecs_schema_flattened.update({index: info["type"]})
        ecs_schema = utils.convert_to_nested_schema(ecs_schema_flattened)
        for index, info in ecs_schema_scaled_floats.items():
            parts = index.split(".")
            current = ecs_schema

            # Traverse the ecs_schema to the correct nested dictionary
            for part in parts[:-1]:  # Traverse all parts except the last one
                current = current.setdefault(part, {}).setdefault("properties", {})

            current[parts[-1]].update({"scaling_factor": info})
        return ecs_schema

    def prepare_mappings(
        self,
        elastic_client: Elasticsearch,
        indices: list[str],
        stack_version: str,
        contents: TOMLRuleContents,
        log: Callable[[str], None],
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        """Prepare index mappings for the given indices and rule integrations."""
        existing_mappings, index_lookup = misc.get_existing_mappings(elastic_client, indices)

        # Collect mappings for the integrations
        rule_integrations = self.get_rule_integrations(contents)

        # Collect mappings for all relevant integrations for the given stack version
        package_manifests = load_integrations_manifests()
        integration_schemas = load_integrations_schemas()

        integration_mappings, integration_index_lookup = self.prepare_integration_mappings(
            rule_integrations, stack_version, package_manifests, integration_schemas, log
        )

        index_lookup.update(integration_index_lookup)

        # Combine existing and integration mappings into a single mapping dict
        combined_mappings: dict[str, Any] = {}
        utils.combine_dicts(combined_mappings, existing_mappings)
        utils.combine_dicts(combined_mappings, integration_mappings)

        # Load non-ecs schema and convert to index mapping format (nested schema)
        non_ecs_mapping: dict[str, Any] = {}
        non_ecs = ecs.get_non_ecs_schema()
        for index in indices:
            non_ecs_mapping.update(non_ecs.get(index, {}))
        non_ecs_mapping = ecs.flatten(non_ecs_mapping)
        non_ecs_mapping = utils.convert_to_nested_schema(non_ecs_mapping)
        if not combined_mappings and not non_ecs_mapping:
            raise ValueError("No mappings found")
        index_lookup.update({"rule-non-ecs-index": non_ecs_mapping})

        # Load ECS in an index mapping format (nested schema)
        current_version = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
        ecs_schema = self.get_ecs_schema_mappings(current_version)

        index_lookup.update({"rule-ecs-index": ecs_schema})

        return existing_mappings, index_lookup, combined_mappings

    def remote_validate_rule(
        self, kibana_client: Kibana, elastic_client: Elasticsearch, contents: TOMLRuleContents, verbosity: int = 0
    ) -> None:
        """Uses remote validation from an Elastic Stack to validate ES|QL a given rule"""
        rule_id = contents.data.rule_id

        def log(val: str) -> None:
            """Log if verbosity is 1 or greater (1 corresponds to `-v` in pytest)"""
            unit_test_verbose_level = 1
            if verbosity >= unit_test_verbose_level:
                print(f"{rule_id}:", val)

        stack_version = ""
        kibana_details: dict[str, Any] = kibana_client.get("/api/status", {})  # type: ignore[reportUnknownVariableType]
        if "version" not in kibana_details:
            raise ValueError("Failed to retrieve Kibana details.")
        stack_version = str(kibana_details["version"]["number"])
        log(f"Validating against {stack_version} stack")

        indices_str, indices = utils.get_esql_query_indices(contents.data.query)  # type: ignore[reportUnknownVariableType]
        log(f"Extracted indices from query: {', '.join(indices)}")

        # Get mappings for all matching existing index templates
        existing_mappings, index_lookup, combined_mappings = self.prepare_mappings(
            elastic_client, indices, stack_version, contents, log
        )
        log(f"Collected mappings: {len(existing_mappings)}")
        log(f"Combined mappings prepared: {len(combined_mappings)}")

        # Create remote indices
        full_index_str = self.create_remote_indices(elastic_client, existing_mappings, index_lookup, log)
        utils.combine_dicts(combined_mappings, index_lookup["rule-non-ecs-index"])
        utils.combine_dicts(combined_mappings, index_lookup["rule-ecs-index"])

        # Replace all sources with the test indices
        query = contents.data.query  # type: ignore[reportUnknownVariableType]
        query = query.replace(indices_str, full_index_str)  # type: ignore[reportUnknownVariableType]

        # TODO these query_columns are the unique fields
        query_columns = self.execute_query_against_indices(elastic_client, query, full_index_str, log)  # type: ignore[reportUnknownVariableType]

        # Validate that all fields (columns) are either dynamic fields or correctly mapped
        # against the combined mapping of all the indices
        if self.validate_columns_index_mapping(query_columns, combined_mappings):
            log("All dynamic columns have proper formatting.")
        else:
            log("Dynamic column(s) have improper formatting.")


def extract_error_field(source: str, exc: eql.EqlParseError | kql.KqlParseError) -> str | None:
    """Extract the field name from an EQL or KQL parse error."""
    lines = source.splitlines()
    mod = -1 if exc.line == len(lines) else 0  # type: ignore[reportUnknownMemberType]
    line = lines[exc.line + mod]  # type: ignore[reportUnknownMemberType]
    start = exc.column  # type: ignore[reportUnknownMemberType]
    stop = start + len(exc.caret.strip())  # type: ignore[reportUnknownVariableType]
    return re.sub(r"^\W+|\W+$", "", line[start:stop])  # type: ignore[reportUnknownArgumentType]

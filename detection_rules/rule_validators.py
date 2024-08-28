# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Validation logic for rules containing queries."""
import re
from enum import Enum
from functools import cached_property, wraps
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import eql
from eql import ast
from eql.parser import KvTree, LarkToEQL, NodeInfo, TypeHint
from eql.parser import _parse as base_parse
from marshmallow import ValidationError
from semver import Version

import kql

from . import ecs, endgame
from .config import CUSTOM_RULES_DIR, load_current_package_version, parse_rules_config
from .custom_schemas import update_auto_generated_schema
from .integrations import (get_integration_schema_data,
                           load_integrations_manifests)
from .rule import (EQLRuleData, QueryRuleData, QueryValidator, RuleMeta,
                   TOMLRuleContents, set_eql_config)
from .schemas import get_stack_schemas

EQL_ERROR_TYPES = Union[eql.EqlCompileError,
                        eql.EqlError,
                        eql.EqlParseError,
                        eql.EqlSchemaError,
                        eql.EqlSemanticError,
                        eql.EqlSyntaxError,
                        eql.EqlTypeMismatchError]
KQL_ERROR_TYPES = Union[kql.KqlCompileError, kql.KqlParseError]
RULES_CONFIG = parse_rules_config()


class ExtendedTypeHint(Enum):
    IP = "ip"

    @classmethod
    def primitives(cls):
        """Get all primitive types."""
        return TypeHint.Boolean, TypeHint.Numeric, TypeHint.Null, TypeHint.String, ExtendedTypeHint.IP

    def is_primitive(self):
        """Check if a type is a primitive."""
        return self in self.primitives()


def custom_in_set(self, node: KvTree) -> NodeInfo:
    """Override and address the limitations of the eql in_set method."""
    # return BaseInSetMethod(self, node)
    outer, container = self.visit(node.child_trees)  # type: (NodeInfo, list[NodeInfo])

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
    def wrapper(query: str, start: Optional[str] = None, **kwargs: Dict[str, Any]) -> Any:
        original_in_set = LarkToEQL.in_set
        LarkToEQL.in_set = custom_in_set
        try:
            result = func(query, start=start, **kwargs)
        finally:  # Using finally to ensure that the original method is restored
            LarkToEQL.in_set = original_in_set
        return result

    return wrapper


eql.parser._parse = custom_base_parse_decorator(base_parse)


class KQLValidator(QueryValidator):
    """Specific fields for KQL query event types."""

    @cached_property
    def ast(self) -> kql.ast.Expression:
        return kql.parse(self.query, normalize_kql_keywords=RULES_CONFIG.normalize_kql_keywords)

    @cached_property
    def unique_fields(self) -> List[str]:
        return list(set(str(f) for f in self.ast if isinstance(f, kql.ast.Field)))

    def auto_add_field(self, validation_checks_error: kql.errors.KqlParseError, index_or_dataview: str) -> None:
        """Auto add a missing field to the schema."""
        field_name = extract_error_field(self.query, validation_checks_error)
        field_type = ecs.get_all_flattened_schema().get(field_name)
        update_auto_generated_schema(index_or_dataview, field_name, field_type)

    def to_eql(self) -> eql.ast.Expression:
        return kql.to_eql(self.query)

    def validate(self, data: QueryRuleData, meta: RuleMeta, max_attempts: int = 10) -> None:
        """Validate the query, called from the parent which contains [metadata] information."""
        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            # syntax only, which is done via self.ast
            return

        if isinstance(data, QueryRuleData) and data.language != 'lucene':
            packages_manifest = load_integrations_manifests()
            package_integrations = TOMLRuleContents.get_packaged_integrations(data, meta, packages_manifest)
            for _ in range(max_attempts):
                validation_checks = {"stack": None, "integrations": None}
                # validate the query against fields within beats
                validation_checks["stack"] = self.validate_stack_combos(data, meta)

                if package_integrations:
                    # validate the query against related integration fields
                    validation_checks["integrations"] = self.validate_integration(data, meta, package_integrations)

                if (validation_checks["stack"] and not package_integrations):
                    # if auto add, try auto adding and then call stack_combo validation again
                    if validation_checks["stack"].error_msg == "Unknown field" and RULES_CONFIG.auto_gen_schema_file:
                        # auto add the field and re-validate
                        self.auto_add_field(validation_checks["stack"], data.index_or_dataview[0])
                    else:
                        raise validation_checks["stack"]

                if (validation_checks["stack"] and validation_checks["integrations"]):
                    # if auto add, try auto adding and then call stack_combo validation again
                    if validation_checks["stack"].error_msg == "Unknown field" and RULES_CONFIG.auto_gen_schema_file:
                        # auto add the field and re-validate
                        self.auto_add_field(validation_checks["stack"], data.index_or_dataview[0])
                    else:
                        raise ValueError(f"Error in both stack and integrations checks: {validation_checks}")

                else:
                    break

            else:
                raise ValueError(f"Maximum validation attempts exceeded for {data.rule_id} - {data.name}")

    def validate_stack_combos(self, data: QueryRuleData, meta: RuleMeta) -> Union[KQL_ERROR_TYPES, None, TypeError]:
        """Validate the query against ECS and beats schemas across stack combinations."""
        for stack_version, mapping in meta.get_validation_stack_versions().items():
            beats_version = mapping['beats']
            ecs_version = mapping['ecs']
            err_trailer = f'stack: {stack_version}, beats: {beats_version}, ecs: {ecs_version}'

            beat_types, beat_schema, schema = self.get_beats_schema(data.index_or_dataview,
                                                                    beats_version, ecs_version)

            try:
                kql.parse(self.query, schema=schema, normalize_kql_keywords=RULES_CONFIG.normalize_kql_keywords)
            except kql.KqlParseError as exc:
                message = exc.error_msg
                trailer = err_trailer
                if "Unknown field" in message and beat_types:
                    trailer = f"\nTry adding event.module or event.dataset to specify beats module\n\n{trailer}"

                return kql.KqlParseError(exc.error_msg, exc.line, exc.column, exc.source,
                                         len(exc.caret.lstrip()), trailer=trailer)
            except Exception as exc:
                print(err_trailer)
                return exc

    def validate_integration(
        self, data: QueryRuleData, meta: RuleMeta, package_integrations: List[dict]
    ) -> Union[KQL_ERROR_TYPES, None, TypeError]:
        """Validate the query, called from the parent which contains [metadata] information."""
        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            return

        error_fields = {}
        package_schemas = {}

        # Initialize package_schemas with a nested structure
        for integration_data in package_integrations:
            package = integration_data["package"]
            integration = integration_data["integration"]
            if integration:
                package_schemas.setdefault(package, {}).setdefault(integration, {})
            else:
                package_schemas.setdefault(package, {})

        # Process each integration schema
        for integration_schema_data in get_integration_schema_data(
            data, meta, package_integrations
        ):
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
                kql.parse(self.query,
                          schema=integration_schema,
                          normalize_kql_keywords=RULES_CONFIG.normalize_kql_keywords)
            except kql.KqlParseError as exc:
                if exc.error_msg == "Unknown field":
                    field = extract_error_field(self.query, exc)
                    trailer = (
                        f"\n\tTry adding event.module or event.dataset to specify integration module\n\t"
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
                        print(
                            f"\nWarning: `{field}` in `{data.name}` not found in schema. {trailer}"
                        )
                else:
                    return kql.KqlParseError(
                        exc.error_msg,
                        exc.line,
                        exc.column,
                        exc.source,
                        len(exc.caret.lstrip()),
                        exc.trailer,
                    )

        # Check error fields against schemas of different packages or different integrations
        for field, error_data in list(error_fields.items()):
            error_package, error_integration = (
                error_data["package"],
                error_data["integration"],
            )
            for package, integrations_or_schema in package_schemas.items():
                if error_integration is None:
                    # Compare against the schema directly if there's no integration
                    if error_package != package and field in integrations_or_schema:
                        del error_fields[field]
                        break
                else:
                    # Compare against integration schemas
                    for integration, schema in integrations_or_schema.items():
                        check_alt_schema = (
                            error_package != package or  # noqa: W504
                            (error_package == package and error_integration != integration)
                        )
                        if check_alt_schema and field in schema:
                            del error_fields[field]

        # Raise the first error
        if error_fields:
            _, error_data = next(iter(error_fields.items()))
            return kql.KqlParseError(
                error_data["error"].error_msg,
                error_data["error"].line,
                error_data["error"].column,
                error_data["error"].source,
                len(error_data["error"].caret.lstrip()),
                error_data["trailer"],
            )


class EQLValidator(QueryValidator):
    """Specific fields for EQL query event types."""

    @cached_property
    def ast(self) -> eql.ast.Expression:
        latest_version = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
        cfg = set_eql_config(str(latest_version))
        with eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions, eql.parser.skip_optimizations, cfg:
            return eql.parse_query(self.query)

    def text_fields(self, eql_schema: Union[ecs.KqlSchema2Eql, endgame.EndgameSchema]) -> List[str]:
        """Return a list of fields of type text."""
        from kql.parser import elasticsearch_type_family
        schema = eql_schema.kql_schema if isinstance(eql_schema, ecs.KqlSchema2Eql) else eql_schema.endgame_schema

        return [f for f in self.unique_fields if elasticsearch_type_family(schema.get(f)) == 'text']

    @cached_property
    def unique_fields(self) -> List[str]:
        return list(set(str(f) for f in self.ast if isinstance(f, eql.ast.Field)))

    def auto_add_field(self, validation_checks_error: eql.errors.EqlParseError, index_or_dataview: str) -> None:
        """Auto add a missing field to the schema."""
        field_name = extract_error_field(self.query, validation_checks_error)
        field_type = ecs.get_all_flattened_schema().get(field_name)
        update_auto_generated_schema(index_or_dataview, field_name, field_type)

    def validate(self, data: "QueryRuleData", meta: RuleMeta, max_attempts: int = 10) -> None:
        """Validate an EQL query while checking TOMLRule."""
        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            # syntax only, which is done via self.ast
            return

        if isinstance(data, QueryRuleData) and data.language != "lucene":
            packages_manifest = load_integrations_manifests()
            package_integrations = TOMLRuleContents.get_packaged_integrations(data, meta, packages_manifest)

            for _ in range(max_attempts):
                validation_checks = {"stack": None, "integrations": None}
                # validate the query against fields within beats
                validation_checks["stack"] = self.validate_stack_combos(data, meta)

                if package_integrations:
                    # validate the query against related integration fields
                    validation_checks["integrations"] = self.validate_integration(data, meta, package_integrations)

                if validation_checks["stack"] and not package_integrations:
                    # if auto add, try auto adding and then validate again
                    if (
                        "Field not recognized" in validation_checks["stack"].error_msg
                        and RULES_CONFIG.auto_gen_schema_file  # noqa: W503
                    ):
                        # auto add the field and re-validate
                        self.auto_add_field(validation_checks["stack"], data.index_or_dataview[0])
                    else:
                        raise validation_checks["stack"]

                elif validation_checks["stack"] and validation_checks["integrations"]:
                    # if auto add, try auto adding and then validate again
                    if (
                        "Field not recognized" in validation_checks["stack"].error_msg
                        and RULES_CONFIG.auto_gen_schema_file  # noqa: W503
                    ):
                        # auto add the field and re-validate
                        self.auto_add_field(validation_checks["stack"], data.index_or_dataview[0])
                    else:
                        raise ValueError(f"Error in both stack and integrations checks: {validation_checks}")

                else:
                    break

            else:
                raise ValueError(f"Maximum validation attempts exceeded for {data.rule_id} - {data.name}")

            rule_type_config_fields, rule_type_config_validation_failed = self.validate_rule_type_configurations(
                data, meta
            )
            if rule_type_config_validation_failed:
                raise ValueError(
                    f"""Rule type config values are not ECS compliant, check these values:
                                {rule_type_config_fields}"""
                )

    def validate_stack_combos(self, data: QueryRuleData, meta: RuleMeta) -> Union[EQL_ERROR_TYPES, None, ValueError]:
        """Validate the query against ECS and beats schemas across stack combinations."""
        for stack_version, mapping in meta.get_validation_stack_versions().items():
            beats_version = mapping['beats']
            ecs_version = mapping['ecs']
            endgame_version = mapping['endgame']
            err_trailer = f'stack: {stack_version}, beats: {beats_version},' \
                          f'ecs: {ecs_version}, endgame: {endgame_version}'

            beat_types, beat_schema, schema = self.get_beats_schema(data.index_or_dataview,
                                                                    beats_version, ecs_version)
            endgame_schema = self.get_endgame_schema(data.index_or_dataview, endgame_version)
            eql_schema = ecs.KqlSchema2Eql(schema)

            # validate query against the beats and eql schema
            exc = self.validate_query_with_schema(data=data, schema=eql_schema, err_trailer=err_trailer,
                                                  beat_types=beat_types, min_stack_version=meta.min_stack_version)
            if exc:
                return exc

            if endgame_schema:
                # validate query against the endgame schema
                exc = self.validate_query_with_schema(data=data, schema=endgame_schema, err_trailer=err_trailer,
                                                      min_stack_version=meta.min_stack_version)
                if exc:
                    raise exc

    def validate_integration(self, data: QueryRuleData, meta: RuleMeta,
                             package_integrations: List[dict]) -> Union[EQL_ERROR_TYPES, None, ValueError]:
        """Validate an EQL query while checking TOMLRule against integration schemas."""
        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            # syntax only, which is done via self.ast
            return

        error_fields = {}
        package_schemas = {}

        # Initialize package_schemas with a nested structure
        for integration_data in package_integrations:
            package = integration_data["package"]
            integration = integration_data["integration"]
            if integration:
                package_schemas.setdefault(package, {}).setdefault(integration, {})
            else:
                package_schemas.setdefault(package, {})

        # Process each integration schema
        for integration_schema_data in get_integration_schema_data(
            data, meta, package_integrations
        ):
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
                min_stack_version=meta.min_stack_version,
            )

            if isinstance(exc, eql.EqlParseError):
                message = exc.error_msg
                if message == "Unknown field" or "Field not recognized" in message:
                    field = extract_error_field(self.query, exc)
                    trailer = (
                        f"\n\tTry adding event.module or event.dataset to specify integration module\n\t"
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
                        print(
                            f"\nWarning: `{field}` in `{data.name}` not found in schema. {trailer}"
                        )
                else:
                    return exc

        # Check error fields against schemas of different packages or different integrations
        for field, error_data in list(error_fields.items()):
            error_package, error_integration = (
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
                        check_alt_schema = (
                            error_package != package or  # noqa: W504
                            (error_package == package and error_integration != integration)
                        )
                        if check_alt_schema and field in schema:
                            del error_fields[field]

        # raise the first error
        if error_fields:
            _, data = next(iter(error_fields.items()))
            exc = data["error"]
            return exc

    def validate_query_with_schema(self, data: 'QueryRuleData', schema: Union[ecs.KqlSchema2Eql, endgame.EndgameSchema],
                                   err_trailer: str, min_stack_version: str, beat_types: list = None) -> Union[
            EQL_ERROR_TYPES, ValueError, None]:
        """Validate the query against the schema."""
        try:
            config = set_eql_config(min_stack_version)
            with config, schema, eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
                eql.parse_query(self.query)
        except eql.EqlParseError as exc:
            message = exc.error_msg
            trailer = err_trailer
            if "Unknown field" in message and beat_types:
                trailer = f"\nTry adding event.module or event.dataset to specify beats module\n\n{trailer}"
            elif "Field not recognized" in message:
                text_fields = self.text_fields(schema)
                if text_fields:
                    fields_str = ', '.join(text_fields)
                    trailer = f"\neql does not support text fields: {fields_str}\n\n{trailer}"

            return exc.__class__(exc.error_msg, exc.line, exc.column, exc.source,
                                 len(exc.caret.lstrip()), trailer=trailer)

        except Exception as exc:
            print(err_trailer)
            return exc

    def validate_rule_type_configurations(self, data: EQLRuleData, meta: RuleMeta) -> \
            Tuple[List[Optional[str]], bool]:
        """Validate EQL rule type configurations."""
        if data.timestamp_field or data.event_category_override or data.tiebreaker_field:

            # get a list of rule type configuration fields
            # Get a list of rule type configuration fields
            fields = ["timestamp_field", "event_category_override", "tiebreaker_field"]
            set_fields = list(filter(None, (data.get(field) for field in fields)))

            # get stack_version and ECS schema
            min_stack_version = meta.get("min_stack_version")
            if min_stack_version is None:
                min_stack_version = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
            ecs_version = get_stack_schemas()[str(min_stack_version)]['ecs']
            schema = ecs.get_schema(ecs_version)

            # return a list of rule type config field values and whether any are not in the schema
            return (set_fields, any([f not in schema.keys() for f in set_fields]))
        else:
            # if rule type fields are not set, return an empty list and False
            return [], False


class ESQLValidator(QueryValidator):
    """Validate specific fields for ESQL query event types."""

    @cached_property
    def ast(self):
        return None

    @cached_property
    def unique_fields(self) -> List[str]:
        """Return a list of unique fields in the query."""
        # return empty list for ES|QL rules until ast is available (friendlier than raising error)
        # raise NotImplementedError('ES|QL query parsing not yet supported')
        return []

    def validate(self, data: 'QueryRuleData', meta: RuleMeta) -> None:
        """Validate an ESQL query while checking TOMLRule."""
        # temporarily override to NOP until ES|QL query parsing is supported

    def validate_integration(self, data: QueryRuleData, meta: RuleMeta, package_integrations: List[dict]) -> Union[
            ValidationError, None, ValueError]:
        # return self.validate(data, meta)
        pass


def extract_error_field(source: str, exc: Union[eql.EqlParseError, kql.KqlParseError]) -> Optional[str]:
    """Extract the field name from an EQL or KQL parse error."""
    lines = source.splitlines()
    mod = -1 if exc.line == len(lines) else 0
    line = lines[exc.line + mod]
    start = exc.column
    stop = start + len(exc.caret.strip())
    return re.sub(r'^\W+|\W+$', '', line[start:stop])

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Validation logic for rules containing queries."""
from functools import cached_property
from typing import List, Optional, Union

import eql

import kql

from . import ecs, endgame
from .integrations import get_integration_schema_data, load_integrations_manifests
from .rule import QueryRuleData, QueryValidator, RuleMeta, TOMLRuleContents


class KQLValidator(QueryValidator):
    """Specific fields for KQL query event types."""

    @cached_property
    def ast(self) -> kql.ast.Expression:
        return kql.parse(self.query)

    @cached_property
    def unique_fields(self) -> List[str]:
        return list(set(str(f) for f in self.ast if isinstance(f, kql.ast.Field)))

    def to_eql(self) -> eql.ast.Expression:
        return kql.to_eql(self.query)

    def validate(self, data: QueryRuleData, meta: RuleMeta) -> None:
        """Validate the query, called from the parent which contains [metadata] information."""
        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            # syntax only, which is done via self.ast
            return

        if isinstance(data, QueryRuleData) and data.language != 'lucene':
            packages_manifest = load_integrations_manifests()
            package_integrations = TOMLRuleContents.get_packaged_integrations(data, meta, packages_manifest)

            # validate the query against fields within beats
            self.validate_stack_combos(data, meta)

            if package_integrations:
                # validate the query against related integration fields
                self.validate_integration(data, meta, package_integrations)

    def validate_stack_combos(self, data: QueryRuleData, meta: RuleMeta) -> None:
        """Validate the query against ECS and beats schemas across stack combinations."""
        for stack_version, mapping in meta.get_validation_stack_versions().items():
            beats_version = mapping['beats']
            ecs_version = mapping['ecs']
            err_trailer = f'stack: {stack_version}, beats: {beats_version}, ecs: {ecs_version}'

            beat_types, beat_schema, schema = self.get_beats_schema(data.index or [],
                                                                    beats_version, ecs_version)

            try:
                kql.parse(self.query, schema=schema)
            except kql.KqlParseError as exc:
                message = exc.error_msg
                trailer = err_trailer
                if "Unknown field" in message and beat_types:
                    trailer = f"\nTry adding event.module or event.dataset to specify beats module\n\n{trailer}"

                raise kql.KqlParseError(exc.error_msg, exc.line, exc.column, exc.source,
                                        len(exc.caret.lstrip()), trailer=trailer) from None
            except Exception:
                print(err_trailer)
                raise

    def validate_integration(self, data: QueryRuleData, meta: RuleMeta, package_integrations: List[dict]) -> None:
        """Validate the query, called from the parent which contains [metadata] information."""
        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            # syntax only, which is done via self.ast
            return

        error_fields = {}
        current_stack_version = ""
        combined_schema = {}
        for integration_schema_data in get_integration_schema_data(data, meta, package_integrations):
            ecs_version = integration_schema_data['ecs_version']
            integration = integration_schema_data['integration']
            package = integration_schema_data['package']
            package_version = integration_schema_data['package_version']
            integration_schema = integration_schema_data['schema']
            stack_version = integration_schema_data['stack_version']

            if stack_version != current_stack_version:
                # reset the combined schema for each stack version
                current_stack_version = stack_version
                combined_schema = {}

            # add non-ecs-schema fields for edge cases not added to the integration
            for index_name in data.index:
                integration_schema.update(**ecs.flatten(ecs.get_index_schema(index_name)))
            combined_schema.update(**integration_schema)

            try:
                # validate the query against the integration fields with the package version
                kql.parse(self.query, schema=integration_schema)
            except kql.KqlParseError as exc:
                if exc.error_msg == "Unknown field":
                    field = extract_error_field(exc)
                    trailer = (f"\n\tTry adding event.module or event.dataset to specify integration module\n\t"
                               f"Will check against integrations {meta.integration} combined.\n\t"
                               f"{package=}, {integration=}, {package_version=}, "
                               f"{stack_version=}, {ecs_version=}"
                               )
                    error_fields[field] = {"error": exc, "trailer": trailer}
                    if data.get("notify", False):
                        print(f"\nWarning: `{field}` in `{data.name}` not found in schema. {trailer}")
                else:
                    raise kql.KqlParseError(exc.error_msg, exc.line, exc.column, exc.source,
                                            len(exc.caret.lstrip()), trailer=trailer) from None

        # don't error on fields that are in another integration schema
        for field in list(error_fields.keys()):
            if field in combined_schema:
                del error_fields[field]

        # raise the first error
        if error_fields:
            _, data = next(iter(error_fields.items()))
            exc = data["error"]
            trailer = data["trailer"]

            raise kql.KqlParseError(exc.error_msg, exc.line, exc.column, exc.source,
                                    len(exc.caret.lstrip()), trailer=trailer) from None


class EQLValidator(QueryValidator):
    """Specific fields for EQL query event types."""

    @cached_property
    def ast(self) -> eql.ast.Expression:
        with eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
            return eql.parse_query(self.query)

    def text_fields(self, eql_schema: Union[ecs.KqlSchema2Eql, endgame.EndgameSchema]) -> List[str]:
        """Return a list of fields of type text."""
        from kql.parser import elasticsearch_type_family
        schema = eql_schema.kql_schema if isinstance(eql_schema, ecs.KqlSchema2Eql) else eql_schema.endgame_schema

        return [f for f in self.unique_fields if elasticsearch_type_family(schema.get(f)) == 'text']

    @cached_property
    def unique_fields(self) -> List[str]:
        return list(set(str(f) for f in self.ast if isinstance(f, eql.ast.Field)))

    def validate(self, data: 'QueryRuleData', meta: RuleMeta) -> None:
        """Validate an EQL query while checking TOMLRule."""
        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            # syntax only, which is done via self.ast
            return

        if isinstance(data, QueryRuleData) and data.language != 'lucene':
            packages_manifest = load_integrations_manifests()
            package_integrations = TOMLRuleContents.get_packaged_integrations(data, meta, packages_manifest)

            # validate the query against fields within beats
            self.validate_stack_combos(data, meta)

            if package_integrations:
                # validate the query against related integration fields
                self.validate_integration(data, meta, package_integrations)

    def validate_stack_combos(self, data: QueryRuleData, meta: RuleMeta) -> None:
        """Validate the query against ECS and beats schemas across stack combinations."""
        for stack_version, mapping in meta.get_validation_stack_versions().items():
            beats_version = mapping['beats']
            ecs_version = mapping['ecs']
            endgame_version = mapping['endgame']
            err_trailer = f'stack: {stack_version}, beats: {beats_version},' \
                          f'ecs: {ecs_version}, endgame: {endgame_version}'

            beat_types, beat_schema, schema = self.get_beats_schema(data.index or [],
                                                                    beats_version, ecs_version)
            endgame_schema = self.get_endgame_schema(data.index, endgame_version)
            eql_schema = ecs.KqlSchema2Eql(schema)

            # validate query against the beats and eql schema
            self.validate_query_with_schema(data=data, schema=eql_schema, err_trailer=err_trailer,
                                            beat_types=beat_types)

            if endgame_schema:
                # validate query against the endgame schema
                self.validate_query_with_schema(data=data, schema=endgame_schema, err_trailer=err_trailer)

    def validate_integration(self, data: QueryRuleData, meta: RuleMeta, package_integrations: List[dict]) -> None:
        """Validate an EQL query while checking TOMLRule against integration schemas."""
        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            # syntax only, which is done via self.ast
            return

        error_fields = {}
        current_stack_version = ""
        combined_schema = {}
        for integration_schema_data in get_integration_schema_data(data, meta, package_integrations):
            ecs_version = integration_schema_data['ecs_version']
            integration = integration_schema_data['integration']
            package = integration_schema_data['package']
            package_version = integration_schema_data['package_version']
            integration_schema = integration_schema_data['schema']
            stack_version = integration_schema_data['stack_version']

            if stack_version != current_stack_version:
                # reset the combined schema for each stack version
                current_stack_version = stack_version
                combined_schema = {}

            # add non-ecs-schema fields for edge cases not added to the integration
            for index_name in data.index:
                integration_schema.update(**ecs.flatten(ecs.get_index_schema(index_name)))
            combined_schema.update(**integration_schema)

            eql_schema = ecs.KqlSchema2Eql(integration_schema)
            err_trailer = f'stack: {stack_version}, integration: {integration},' \
                          f'ecs: {ecs_version}, package: {package}, package_version: {package_version}'

            try:
                self.validate_query_with_schema(data=data, schema=eql_schema, err_trailer=err_trailer)
            except eql.EqlParseError as exc:
                message = exc.error_msg
                if message == "Unknown field" or "Field not recognized" in message:
                    field = extract_error_field(exc)
                    trailer = (f"\n\tTry adding event.module or event.dataset to specify integration module\n\t"
                               f"Will check against integrations {meta.integration} combined.\n\t"
                               f"{package=}, {integration=}, {package_version=}, "
                               f"{stack_version=}, {ecs_version=}"
                               )
                    error_fields[field] = {"error": exc, "trailer": trailer}
                    if data.get("notify", False):
                        print(f"\nWarning: `{field}` in `{data.name}` not found in schema. {trailer}")
                else:
                    raise exc

        # don't error on fields that are in another integration schema
        for field in list(error_fields.keys()):
            if field in combined_schema:
                del error_fields[field]

        # raise the first error
        if error_fields:
            _, data = next(iter(error_fields.items()))
            exc = data["error"]
            raise exc

    def validate_query_with_schema(self, data: 'QueryRuleData', schema: Union[ecs.KqlSchema2Eql, endgame.EndgameSchema],
                                   err_trailer: str, beat_types: list = None) -> None:
        """Validate the query against the schema."""
        try:
            with schema, eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
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

            raise exc.__class__(exc.error_msg, exc.line, exc.column, exc.source,
                                len(exc.caret.lstrip()), trailer=trailer) from None

        except Exception:
            print(err_trailer)
            raise


def extract_error_field(exc: Union[eql.EqlParseError, kql.KqlParseError]) -> Optional[str]:
    """Extract the field name from an EQL or KQL parse error."""
    lines = exc.source.splitlines()
    mod = -1 if exc.line == len(lines) else 0
    line = lines[exc.line + mod]
    start = exc.column
    stop = start + len(exc.caret.strip())
    return line[start:stop]

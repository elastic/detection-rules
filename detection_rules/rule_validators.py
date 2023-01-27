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

            if package_integrations:
                # validate the query against related integration fields
                print(f"Validating {data.name} against {len(package_integrations)} integration(s)")
                self.validate_integration(data, meta, package_integrations)
            else:
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

        for integration_schema_data in get_integration_schema_data(data, meta, package_integrations):
            ecs_version = integration_schema_data['ecs_version']
            integration = integration_schema_data['integration']
            package = integration_schema_data['package']
            package_version = integration_schema_data['package_version']
            integration_schema = integration_schema_data['schema']
            stack_version = integration_schema_data['stack_version']

            # add non-ecs-schema fields for edge cases not added to the integration
            for index_name in data.index:
                integration_schema.update(**ecs.flatten(ecs.get_index_schema(index_name)))

            try:
                # validate the query against the integration fields with the package version
                kql.parse(self.query, schema=integration_schema)
            except kql.KqlParseError as exc:
                trailer = (f"\nTry adding event.module or event.dataset to specify integration module\n\n"
                           f"{package=}, {integration=}, {package_version=}, "
                           f"{stack_version=}, {ecs_version=}"
                           )

                # TODO: Remove print
                print(f"\n\nError on {data.name}:\n\t{str(exc)} {trailer}")
                # raise kql.KqlParseError(exc.error_msg, exc.line, exc.column, exc.source,
                #                         len(exc.caret.lstrip()), trailer=trailer) from None


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

            # TODO: Remove print
            print(f"\n\nError on {data.name}:\n\t{str(exc)}")
            # raise exc.__class__(exc.error_msg, exc.line, exc.column, exc.source,
            #                     len(exc.caret.lstrip()), trailer=trailer) from None

        except Exception:
            print(err_trailer)
            raise

    def validate(self, data: 'QueryRuleData', meta: RuleMeta) -> None:
        """Validate an EQL query while checking TOMLRule."""
        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            # syntax only, which is done via self.ast
            return

        if isinstance(data, QueryRuleData) and data.language != 'lucene':
            packages_manifest = load_integrations_manifests()
            package_integrations = TOMLRuleContents.get_packaged_integrations(data, meta, packages_manifest)

            if package_integrations:
                # validate the query against related integration fields
                print(f"Validating {data.name} against {len(package_integrations)} integration(s)")
                self.validate_integration(data, meta, package_integrations)

                # Still need to check endgame if it's in the index
                for stack_version, mapping in meta.get_validation_stack_versions().items():
                    endgame_version = mapping['endgame']
                    endgame_schema = self.get_endgame_schema(data.index, endgame_version)
                    if endgame_schema:
                        # validate query against the endgame schema
                        err_trailer = f'stack: {stack_version}, endgame: {endgame_version}'
                        self.validate_query_with_schema(data=data, schema=endgame_schema, err_trailer=err_trailer)

            else:
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

        for integration_schema_data in get_integration_schema_data(data, meta, package_integrations):
            ecs_version = integration_schema_data['ecs_version']
            integration = integration_schema_data['integration']
            package = integration_schema_data['package']
            package_version = integration_schema_data['package_version']
            integration_schema = integration_schema_data['schema']
            stack_version = integration_schema_data['stack_version']

            # add non-ecs-schema fields for edge cases not added to the integration
            for index_name in data.index:
                integration_schema.update(**ecs.flatten(ecs.get_index_schema(index_name)))

            eql_schema = ecs.KqlSchema2Eql(integration_schema)
            err_trailer = f'stack: {stack_version}, integration: {integration},' \
                          f'ecs: {ecs_version}, package: {package}, package_version: {package_version}'

            try:
                self.validate_query_with_schema(data=data, schema=eql_schema, err_trailer=err_trailer)
            except eql.EqlParseError as exc:
                raise exc


def extract_error_field(exc: Union[eql.EqlParseError, kql.KqlParseError]) -> Optional[str]:
    line = exc.source.splitlines()[exc.line]
    start = exc.column
    stop = start + len(exc.caret.strip())
    return line[start:stop]

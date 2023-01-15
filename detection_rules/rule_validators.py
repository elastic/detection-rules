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
from .integrations import (find_compatible_version_window,
                           load_integrations_manifests)
from .rule import QueryRuleData, QueryValidator, RuleMeta, TOMLRuleContents


class KQLValidator(QueryValidator):
    """Specific fields for query event types."""

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

        # validate the query against related integration fields
        print("validating query against integration fields")
        packages_manifest = load_integrations_manifests()
        if isinstance(data, QueryRuleData) and data.language != 'lucene':
            package_integrations = TOMLRuleContents.get_packaged_integrations(data, meta, packages_manifest)

            if not package_integrations:
                return

            for package in package_integrations:
                package_version_window = find_compatible_version_window(package=package["package"],
                                                                        integration=package["integration"],
                                                                        current_stack_version=meta.min_stack_version,
                                                                        packages_manifest=packages_manifest)

                # for each version in the window, validate the query against the integration fields
                for package_version in package_version_window:
                    # validate the query against the integration fields with the package version
                    print(f"validating query against integration fields for {package['integration']} {package_version}")

        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            # syntax only, which is done via self.ast
            return

        for stack_version, mapping in meta.get_validation_stack_versions().items():
            beats_version = mapping['beats']
            ecs_version = mapping['ecs']
            err_trailer = f'stack: {stack_version}, beats: {beats_version}, ecs: {ecs_version}'

            beat_types, beat_schema, schema = self.get_beats_schema(data.index or [], beats_version, ecs_version)

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


class EQLValidator(QueryValidator):

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

    def validate_query_with_schema(self, schema: Union[ecs.KqlSchema2Eql, endgame.EndgameSchema],
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

    def validate(self, data: 'QueryRuleData', meta: RuleMeta) -> None:
        """Validate an EQL query while checking TOMLRule."""
        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            # syntax only, which is done via self.ast
            return

        for stack_version, mapping in meta.get_validation_stack_versions().items():
            beats_version = mapping['beats']
            ecs_version = mapping['ecs']
            endgame_version = mapping['endgame']
            err_trailer = f'stack: {stack_version}, beats: {beats_version},' \
                          f'ecs: {ecs_version}, endgame: {endgame_version}'

            beat_types, beat_schema, schema = self.get_beats_schema(data.index or [], beats_version, ecs_version)
            endgame_schema = self.get_endgame_schema(data.index, endgame_version)
            eql_schema = ecs.KqlSchema2Eql(schema)

            # validate query against the beats and eql schema
            self.validate_query_with_schema(schema=eql_schema, err_trailer=err_trailer, beat_types=beat_types)

            if endgame_schema:
                # validate query against the endgame schema
                self.validate_query_with_schema(schema=endgame_schema, err_trailer=err_trailer)


def extract_error_field(exc: Union[eql.EqlParseError, kql.KqlParseError]) -> Optional[str]:
    line = exc.source.splitlines()[exc.line]
    start = exc.column
    stop = start + len(exc.caret.strip())
    return line[start:stop]

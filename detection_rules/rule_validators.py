# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Validation logic for rules containing queries."""
from functools import cached_property

import eql

import kql
from detection_rules import beats, ecs
from detection_rules.rule import QueryValidator, QueryRuleData, RuleMeta


class KQLValidator(QueryValidator):
    """Specific fields for query event types."""

    @cached_property
    def ast(self) -> kql.ast.Expression:
        return kql.parse(self.query)

    @property
    def unique_fields(self) -> List[str]:
        return list(set(str(f) for f in self.ast if isinstance(f, kql.ast.Field)))

    def to_eql(self) -> eql.ast.Expression:
        return kql.to_eql(self.query)

    def validate(self, data: QueryRuleData, meta: RuleMeta) -> None:
        """Static method to validate the query, called from the parent which contains [metadata] information."""
        ast = self.ast

        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            # syntax only, which is done via self.ast
            return

        indexes = data.index or []
        beats_version = meta.beats_version or beats.get_max_version()
        ecs_versions = meta.ecs_versions or [ecs.get_max_version()]

        beat_types = [index.split("-")[0] for index in indexes if "beat-*" in index]
        beat_schema = beats.get_schema_from_kql(ast, beat_types, version=beats_version) if beat_types else None

        if not ecs_versions:
            kql.parse(self.query, schema=ecs.get_kql_schema(indexes=indexes, beat_schema=beat_schema))
        else:
            for version in ecs_versions:
                schema = ecs.get_kql_schema(version=version, indexes=indexes, beat_schema=beat_schema)

                try:
                    kql.parse(self.query, schema=schema)
                except kql.KqlParseError as exc:
                    message = exc.error_msg
                    trailer = None
                    if "Unknown field" in message and beat_types:
                        trailer = "\nTry adding event.module or event.dataset to specify beats module"

                    raise kql.KqlParseError(exc.error_msg, exc.line, exc.column, exc.source,
                                            len(exc.caret.lstrip()), trailer=trailer) from None


class EQLValidator(QueryValidator):

    @cached_property
    def ast(self) -> kql.ast.Expression:
        with eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
            return eql.parse_query(self.query)

    @property
    def unique_fields(self) -> List[str]:
        return list(set(str(f) for f in self.ast if isinstance(f, eql.ast.Field)))

    def validate(self, data: 'QueryRuleData', meta: RuleMeta) -> None:
        """Validate an EQL query while checking TOMLRule."""
        _ = self.ast

        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            # syntax only, which is done via self.ast
            return

        indexes = data.index or []
        beats_version = meta.beats_version or beats.get_max_version()
        ecs_versions = meta.ecs_versions or [ecs.get_max_version()]

        # TODO: remove once py-eql supports ipv6 for cidrmatch
        # Or, unregister the cidrMatch function and replace it with one that doesn't validate against strict IPv4
        with eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
            parsed = eql.parse_query(self.query)

        beat_types = [index.split("-")[0] for index in indexes if "beat-*" in index]
        beat_schema = beats.get_schema_from_eql(parsed, beat_types, version=beats_version) if beat_types else None

        for version in ecs_versions:
            schema = ecs.get_kql_schema(indexes=indexes, beat_schema=beat_schema, version=version)
            eql_schema = ecs.KqlSchema2Eql(schema)

            try:
                # TODO: switch to custom cidrmatch that allows ipv6
                with eql_schema, eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
                    eql.parse_query(self.query)

            except eql.EqlTypeMismatchError:
                raise

            except eql.EqlParseError as exc:
                message = exc.error_msg
                trailer = None
                if "Unknown field" in message and beat_types:
                    trailer = "\nTry adding event.module or event.dataset to specify beats module"

                raise exc.__class__(exc.error_msg, exc.line, exc.column, exc.source,
                                    len(exc.caret.lstrip()), trailer=trailer) from None

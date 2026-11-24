# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Tests for Lucene regex validation of EQL `regex`/`regex~` patterns.

The patterns are validated by the `eql` parser under `elasticsearch_syntax`, so every path that parses EQL is
covered: EQL rules, per-schema subquery validation and nested ES|QL `EQL()` payloads.
"""

from typing import Any

import eql
import esql
import pytest

from detection_rules import ecs
from detection_rules.esql_errors import EsqlSemanticError
from detection_rules.rule import set_esql_config
from detection_rules.rule_loader import RuleCollection
from detection_rules.rule_validators import EQLValidator, ESQLValidator

from .base import BaseRuleTest
from .test_python_library import mk_metadata, mk_rule

LUCENE_ERROR = "Invalid Lucene regular expression"
# First stack version where ES|QL registers the nested EQL() function
NESTED_EQL_STACK_VERSION = "9.7.0"


class TestEQLRegexValidation(BaseRuleTest):
    """Test that EQL rule validation rejects regex patterns Elasticsearch cannot compile."""

    @staticmethod
    def build_rule(query: str) -> dict[str, Any]:
        return {
            "metadata": mk_metadata(["endpoint"]),
            "rule": mk_rule(
                name="Fake Test Rule",
                rule_id="4fffae5d-8b7d-4e48-88b1-979ed42fd9a3",
                description="Test Rule.",
                risk_score=47,
                query=query,
            ),
        }

    def test_unescaped_operators_fail(self) -> None:
        queries = [
            'process where process.command_line regex~ """.*(;|&&|>|<).*"""',
            'process where process.command_line regex """.*<script>.*"""',
            'process where process.command_line regex ("foo.*", ".*~")',
        ]
        for query in queries:
            with self.subTest(query=query), self.assertRaisesRegex(eql.EqlSemanticError, LUCENE_ERROR):
                _ = RuleCollection().load_dict(self.build_rule(query))

    def test_escaped_operators_pass(self) -> None:
        queries = [
            r'process where process.command_line regex~ """.*(;|\&\&|\>|\<).*"""',
            'process where process.command_line regex~ ".*(;|\\\\&\\\\&|\\\\>|\\\\<).*"',
            'process where process.command_line regex """.*[<>&].*"""',
        ]
        for query in queries:
            with self.subTest(query=query):
                _ = RuleCollection().load_dict(self.build_rule(query))

    def test_like_literal_alternatives_pass(self) -> None:
        query = 'process where process.command_line like~ ("*;*", "*&&*", "*>*", "*<*")'
        _ = RuleCollection().load_dict(self.build_rule(query))

    def test_query_text_validation_rejects_pattern(self) -> None:
        """The per-schema path used for sequence subqueries must also reject the pattern."""
        validator = EQLValidator("process where true")
        schema = ecs.KqlSchema2Eql({"process.command_line": "keyword"})

        exc, _ = validator.validate_query_text_with_schema(
            'process where process.command_line regex~ ".*<script>.*"', schema, "", ""
        )
        assert isinstance(exc, eql.EqlSemanticError)
        assert LUCENE_ERROR in str(exc)

        exc, _ = validator.validate_query_text_with_schema(
            r'process where process.command_line regex~ """.*\<script\>.*"""', schema, "", ""
        )
        assert exc is None


class TestNestedEQLRegexValidation:
    """Test that nested ES|QL `EQL()` payloads get the same Lucene regex validation."""

    INVALID = (
        'process where process.command_line regex~ """.*(;|&&|>|<).*"""',
        'sequence [process where true] [network where destination.domain regex ".*<script>.*"]',
        # expression fragments fall back to eql.parse_expression()
        'process.command_line regex~ ".*<script>.*"',
        'process.pid == 4 and process.command_line regex ("foo.*", ".*~")',
    )
    VALID = (
        r'process where process.command_line regex~ """.*(;|\&\&|\>|\<).*"""',
        r'process.command_line regex~ """.*\<script\>.*"""',
        'process.command_line like~ ("*;*", "*&&*", "*>*", "*<*")',
    )

    def test_eql_parse_hook_rejects_invalid_patterns(self) -> None:
        eql_parse = set_esql_config(NESTED_EQL_STACK_VERSION).context["eql_parse"]
        for text in self.INVALID:
            with pytest.raises(eql.EqlSemanticError, match=LUCENE_ERROR):
                eql_parse(text)

    def test_eql_parse_hook_accepts_valid_patterns(self) -> None:
        eql_parse = set_esql_config(NESTED_EQL_STACK_VERSION).context["eql_parse"]
        for text in self.VALID:
            assert eql_parse(text) is not None

    @staticmethod
    def esql_query(nested_eql: str) -> str:
        return f'FROM logs-endpoint.events.process-* | WHERE EQL("""{nested_eql}""") | KEEP process.command_line'

    def test_nested_eql_in_esql_query(self) -> None:
        """Parsing the ES|QL query itself surfaces the Lucene error from the nested EQL() payload."""
        cfg = set_esql_config(NESTED_EQL_STACK_VERSION)
        with cfg, esql.Schema({}, allow_missing=True):
            with pytest.raises(esql.EsqlNestedQueryError, match=LUCENE_ERROR) as exc_info:
                _ = esql.parse_query(self.esql_query('process.command_line regex~ ".*<script>.*" and process.pid > 0'))
            assert isinstance(exc_info.value.inner, eql.EqlSemanticError)

            # a full event query must report the Lucene error too, not the expression fallback's syntax error
            with pytest.raises(esql.EsqlNestedQueryError, match=LUCENE_ERROR):
                _ = esql.parse_query(
                    self.esql_query('process where process.command_line regex~ ".*<script>.*" and process.pid > 0')
                )

            _ = esql.parse_query(self.esql_query(r'process.command_line regex~ ".*\\<script\\>.*" and process.pid > 0'))

    def test_nested_schema_validation_rejects_pattern(self) -> None:
        """The schema pass over nested EQL() payloads must reject the pattern on its own, without the parse hook."""
        cfg = set_esql_config(NESTED_EQL_STACK_VERSION)
        del cfg.context["eql_parse"]
        schema = {"process.command_line": "keyword", "process.pid": "long"}
        validator = ESQLValidator("FROM logs-endpoint.events.process-*")

        def validate(nested_eql: str) -> Exception | None:
            with cfg, esql.Schema({}, allow_missing=True):
                tree = esql.parse_query(self.esql_query(nested_eql))
            return validator._validate_nested_queries_with_schema(tree, schema, "", NESTED_EQL_STACK_VERSION)  # noqa: SLF001

        for nested_eql in (
            'process.command_line regex~ ".*<script>.*" and process.pid > 0',
            'process where process.command_line regex~ ".*<script>.*" and process.pid > 0',
        ):
            exc = validate(nested_eql)
            assert isinstance(exc, EsqlSemanticError)
            assert LUCENE_ERROR in str(exc)

        assert validate(r'process.command_line regex~ ".*\\<script\\>.*" and process.pid > 0') is None

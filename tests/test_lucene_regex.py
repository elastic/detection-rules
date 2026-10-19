# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Tests for Lucene regex validation of EQL `regex`/`regex~` patterns."""

import unittest
from typing import Any

from detection_rules.lucene_regex import LuceneRegexError, validate_lucene_regex
from detection_rules.rule_loader import RuleCollection

from .base import BaseRuleTest
from .test_python_library import mk_metadata, mk_rule


class TestLuceneRegexSyntax(unittest.TestCase):
    """Test the port of Lucene's regex parser."""

    def test_valid_patterns(self) -> None:
        patterns = [
            "",
            ".*",
            "[a-z]+",
            "[^a-z0-9_]",
            r"\d+\.\w+\s\S\W\D",
            r".*[\\/]cmd\.exe",
            "a{2}b{2,}c{2,5}",
            "(foo|bar)?baz",
            "()",
            # escaped optional operators are literals
            r".*(;|\&\&|\>|\<|\~|\#|\@|\").*",
            # literal operators inside a character class
            '[&<>~#@"]',
            # intended use of the optional operators
            "foo<1-100>",
            "@&~(foo.*)",
            '"literal.string"',
            "#|abc",
        ]
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                validate_lucene_regex(pattern)

    def test_invalid_patterns(self) -> None:
        patterns = {
            # the NetScaler log poisoning shape: `<` opens an interval that is never closed
            ".*(;|&&|>|<).*": "expected '>'",
            ".*<script>.*": "not found",
            "a<1-b>": "interval syntax error",
            "a<-5>": "interval syntax error",
            "a~": "unexpected end-of-string",
            '.*"quoted.*': "expected '\"'",
            "(abc": "expected '\\)'",
            "abc)": "end-of-string expected",
            "[abc": "expected '\\]'",
            "[z-a]": "invalid range",
            "a{3,1}": "invalid repetition range",
            "a{,3}": "integer expected",
            "a{3": "expected '}'",
            r"\q": "invalid character class",
            "abc\\": "unexpected end-of-string",
        }
        for pattern, message in patterns.items():
            with self.subTest(pattern=pattern), self.assertRaisesRegex(LuceneRegexError, message):
                validate_lucene_regex(pattern)


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
            with self.subTest(query=query), self.assertRaisesRegex(ValueError, "Invalid Lucene regex"):
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

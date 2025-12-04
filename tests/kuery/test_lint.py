# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import unittest

import kql


class LintTests(unittest.TestCase):
    def validate(self, source, linted, *args):
        self.assertEqual(kql.lint(source), linted, *args)

    def test_lint_field(self):
        self.validate("a : b", "a:b")
        self.validate('"a": b', "a:b")
        self.validate('a : "b"', "a:b")
        self.validate("a : (b)", "a:b")
        self.validate("a:1.234", "a:1.234")
        self.validate('a:"1.234"', "a:1.234")

    def test_upper_tokens(self):
        queries = [
            "a:b AND c:d",
            "a:b OR c:d",
            "NOT a:b",
            "a:(b OR c)",
            "a:(b AND c)",
            "a:(NOT b)",
        ]

        for q in queries:
            with self.assertRaises(kql.KqlParseError):
                kql.parse(q)

        for q in queries:
            # Test query successfully converts and parses
            parsed_query = kql.parse(q, normalize_kql_keywords=True)
            # Test that the parsed query is not equal to the original query, that the transformation was applied
            self.assertNotEqual(str(parsed_query), q, f"Parsed query {parsed_query} matches the original {q}")

    def test_lint_precedence(self):
        self.validate("a:b or (c:d and e:f)", "a:b or c:d and e:f")
        self.validate("(a:b and (c:d or e:f))", "a:b and (c:d or e:f)")

    def test_extract_not(self):
        self.validate("a:(not b)", "not a:b")

    def test_merge_fields(self):
        self.validate("a:b or a:c", "a:(b or c)")
        self.validate("a:b or a:(c or d)", "a:(b or c or d)")
        self.validate("a:b or a:(c or d) or a:e", "a:(b or c or d or e)")

        self.validate("a:b or a:(c and d) or x:y or a:e", "a:(b or e or c and d) or x:y", "Failed to left-align values")
        self.validate("a:b and a:(c and d) or x:y or a:e", "a:(e or b and c and d) or x:y")

    def test_and_not(self):
        self.validate("a:b and not a:c", "a:(b and not c)")

    def test_not_demorgans(self):
        self.validate("not a:b and not a:c and not a:d", "not a:(b or c or d)")
        self.validate("not a:b or not a:c or not a:d", "not a:(b and c and d)")
        self.validate("a:(not b and not c and not d)", "not a:(b or c or d)")
        self.validate("a:(not b or not c or not d)", "not a:(b and c and d)")

    def test_not_or(self):
        self.validate("not (a:1 or a:2)", "not a:(1 or 2)")

    def test_mixed_demorgans(self):
        self.validate("a:(b and not c and not d)", "a:(b and not (c or d))")
        self.validate("a:(b or not c or not d or not e)", "a:(b or not (c and d and e))")
        self.validate("a:((b or not c or not d) and e)", "a:(e and (b or not (c and d)))")

    def test_double_negate(self):
        self.validate("not (not a:b)", "a:b")
        self.validate("a:(not (not b))", "a:b")
        self.validate("not (a:(not b))", "a:b")
        self.validate("not (not (a:b or c:d))", "a:b or c:d")
        self.validate("not (not (a:(not b) or c:(not d)))", "not a:b or not c:d")

    def test_ip(self):
        self.validate("a:ff02\\:\\:fb", 'a:"ff02::fb"')

    def test_compound(self):
        self.validate("a:1 and b:2 and not (c:3 or c:4)", "a:1 and b:2 and not c:(3 or 4)")

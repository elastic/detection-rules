# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import unittest

import kql
from kql.ast import (
    AndExpr,
    Exists,
    Field,
    FieldComparison,
    FieldRange,
    NotExpr,
    NotValue,
    Number,
    String,
    Wildcard,
)


class ParserTests(unittest.TestCase):
    def validate(self, source, tree, *args, **kwargs):
        kwargs.setdefault("optimize", False)
        self.assertEqual(kql.parse(source, *args, **kwargs), tree)

    def test_keyword(self):
        schema = {
            "a.text": "text",
            "a.keyword": "keyword",
            "b": "long",
        }

        self.validate("a.text:hello", FieldComparison(Field("a.text"), String("hello")), schema=schema)
        self.validate("a.keyword:hello", FieldComparison(Field("a.keyword"), String("hello")), schema=schema)

        self.validate('a.text:"hello"', FieldComparison(Field("a.text"), String("hello")), schema=schema)
        self.validate('a.keyword:"hello"', FieldComparison(Field("a.keyword"), String("hello")), schema=schema)

        self.validate("a.text:1", FieldComparison(Field("a.text"), String("1")), schema=schema)
        self.validate("a.keyword:1", FieldComparison(Field("a.keyword"), String("1")), schema=schema)

        self.validate('a.text:"1"', FieldComparison(Field("a.text"), String("1")), schema=schema)
        self.validate('a.keyword:"1"', FieldComparison(Field("a.keyword"), String("1")), schema=schema)

    def test_conversion(self):
        schema = {"num": "long", "text": "text"}

        self.validate("num:1", FieldComparison(Field("num"), Number(1)), schema=schema)
        self.validate('num:"1"', FieldComparison(Field("num"), Number(1)), schema=schema)

        self.validate("text:1", FieldComparison(Field("text"), String("1")), schema=schema)
        self.validate('text:"1"', FieldComparison(Field("text"), String("1")), schema=schema)

    def test_list_equals(self):
        self.assertEqual(kql.parse("a:(1 or 2)", optimize=False), kql.parse("a:(2 or 1)", optimize=False))

    def test_number_exists(self):
        self.assertEqual(kql.parse("foo:*", schema={"foo": "long"}), FieldComparison(Field("foo"), Exists()))

    def test_multiple_types_success(self):
        schema = {"common.a": "keyword", "common.b": "keyword"}
        self.validate('common.* : "hello"', FieldComparison(Field("common.*"), String("hello")), schema=schema)

    def test_multiple_types_fail(self):
        with self.assertRaises(kql.KqlParseError):
            kql.parse('common.* : "hello"', schema={"common.a": "keyword", "common.b": "ip"})

    def test_number_wildcard_fail(self):
        with self.assertRaises(kql.KqlParseError):
            kql.parse("foo:*wc", schema={"foo": "long"})

        with self.assertRaises(kql.KqlParseError):
            kql.parse("foo:wc*", schema={"foo": "long"})

    def test_type_family_success(self):
        kql.parse("abc : 1.2345", schema={"abc": "scaled_float"})
        kql.parse("abc : hello", schema={"abc": "annotated-text"})
        kql.parse("abc >= now-30d", schema={"abc": "date_nanos"})

    def test_type_family_fail(self):
        with self.assertRaises(kql.KqlParseError):
            kql.parse('foo : "hello world"', schema={"foo": "scaled_float"})

    def test_date(self):
        schema = {"@time": "date"}
        self.validate("@time <= now-10d", FieldRange(Field("@time"), "<=", String("now-10d")), schema=schema)

        with self.assertRaises(kql.KqlParseError):
            kql.parse("@time > 5", schema=schema)

    def test_optimization(self):
        query = 'host.name: test-* and not (destination.ip : "127.0.0.53" and destination.ip : "169.254.169.254")'
        dsl_str = str(kql.to_dsl(query))

        bad_case = (
            "{'bool': {'filter': [{'query_string': {'fields': ['host.name'], 'query': 'test-*'}}], "
            "'must_not': [{'match': {'destination.ip': '127.0.0.53'}}, "
            "{'match': {'destination.ip': '169.254.169.254'}}]}}"
        )
        self.assertNotEqual(dsl_str, bad_case, "DSL string matches the bad case, optimization failed.")

        good_case = (
            "{'bool': {'filter': [{'query_string': {'fields': ['host.name'], 'query': 'test-*'}}], "
            "'must_not': [{'bool': {'filter': [{'match': {'destination.ip': '127.0.0.53'}}, "
            "{'match': {'destination.ip': '169.254.169.254'}}]}}]}}"
        )
        self.assertEqual(dsl_str, good_case, "DSL string does not match the good case, optimization failed.")

    def test_blank_space(self):
        with self.assertRaises(kql.KqlParseError):
            kql.lark_parse('"Test-ServiceDaclPermission" or"Update-ExeFunctions"')
            kql.lark_parse('"Test-ServiceDaclPermission"and "Update-ExeFunctions"')
        kql.lark_parse('"Test-ServiceDaclPermission" or "Update-ExeFunctions"')
        kql.lark_parse('"Test-ServiceDaclPermission" \nor "Update-ExeFunctions"')
        kql.lark_parse('"Test-ServiceDaclPermission" or\n "Update-ExeFunctions"')
        kql.lark_parse('"Test-ServiceDaclPermissionOr" or\n "Update-ExeAndFunctions"')

    def test_wildcard_with_spaces(self):
        """Test wildcard values containing spaces (WILDCARD_LITERAL patterns)."""
        # Pattern 1: Starts with * (e.g., *S3 Browser, *S3 Browser*)
        self.validate("field: *S3 Browser*", FieldComparison(Field("field"), Wildcard("*S3 Browser*")))
        self.validate("field: *S3 Browser", FieldComparison(Field("field"), Wildcard("*S3 Browser")))

        # Pattern 2: Ends with * but doesn't start with * (e.g., S3 Browser*)
        self.validate("field: S3 Browser*", FieldComparison(Field("field"), Wildcard("S3 Browser*")))

        # Pattern 3a: Middle * - star appears AFTER a space (e.g., S3 B*owser)
        self.validate("field: S3 B*owser", FieldComparison(Field("field"), Wildcard("S3 B*owser")))

        # Pattern 3b: Middle * - star appears BEFORE a space (e.g., S3* Browser)
        self.validate("field: S3* Browser", FieldComparison(Field("field"), Wildcard("S3* Browser")))

        # Multiple wildcards with spaces
        self.validate("field: foo* bar* baz", FieldComparison(Field("field"), Wildcard("foo* bar* baz")))

    def test_wildcard_with_spaces_and_keywords(self):
        """Test wildcard values containing spaces followed by keywords."""
        # Wildcard followed by 'and' keyword
        result = kql.parse("field: *S3 Browser* and other: value", optimize=False)
        self.assertIsInstance(result, AndExpr)

        # Wildcard followed by 'or' keyword
        result = kql.parse("field: S3 Browser* or other: value", optimize=False)
        self.assertIsNotNone(result)

        # Keywords inside wildcard values (should be part of the wildcard)
        self.validate("field: *or something*", FieldComparison(Field("field"), Wildcard("*or something*")))
        self.validate("field: *not this*", FieldComparison(Field("field"), Wildcard("*not this*")))

    def test_not_prefix_with_wildcard(self):
        """Test NOT keyword is not consumed as part of wildcard literal."""
        # NOT prefix should create NotExpr, not be part of the wildcard
        result = kql.parse("process.executable: not /test/go-build*", optimize=False)
        self.assertIsInstance(result, FieldComparison)
        self.assertIsInstance(result.value, NotValue)
        self.assertIsInstance(result.value.value, Wildcard)
        self.assertEqual(result.value.value.value, "/test/go-build*")

    def test_quoted_wildcard_as_literal(self):
        """Test that quoted wildcards are treated as literal strings, not wildcards."""
        # Quoted wildcard should be a String, not a Wildcard
        self.validate('field: "*text*"', FieldComparison(Field("field"), String("*text*")))

    def test_triple_not_optimization(self):
        """Test that triple NOT optimizes correctly: not(not(not(x))) = not(x)."""
        # Triple NOT should optimize to single NOT
        result = kql.parse("process.name: not not not foo", optimize=True)
        # After optimization, not(not(not(foo))) should become not(foo)
        # The structure is NotExpr(FieldComparison(..., String(...)))
        self.assertIsInstance(result, NotExpr)
        self.assertIsInstance(result.expr, FieldComparison)
        self.assertEqual(result.expr.value.value, "foo")

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import unittest

import kql
from kql.ast import (
    Exists,
    Field,
    FieldComparison,
    FieldRange,
    Number,
    String,
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

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

import unittest
import kql
from kql.ast import (
    Field,
    FieldComparison,
    String,
    Number,
    Exists,
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

        self.validate('a.text:hello', FieldComparison(Field("a.text"), String("hello")), schema=schema)
        self.validate('a.keyword:hello', FieldComparison(Field("a.keyword"), String("hello")), schema=schema)

        self.validate('a.text:"hello"', FieldComparison(Field("a.text"), String("hello")), schema=schema)
        self.validate('a.keyword:"hello"', FieldComparison(Field("a.keyword"), String("hello")), schema=schema)

        self.validate('a.text:1', FieldComparison(Field("a.text"), String("1")), schema=schema)
        self.validate('a.keyword:1', FieldComparison(Field("a.keyword"), String("1")), schema=schema)

        self.validate('a.text:"1"', FieldComparison(Field("a.text"), String("1")), schema=schema)
        self.validate('a.keyword:"1"', FieldComparison(Field("a.keyword"), String("1")), schema=schema)

    def test_conversion(self):
        schema = {"num": "long", "text": "text"}

        self.validate('num:1', FieldComparison(Field("num"), Number(1)), schema=schema)
        self.validate('num:"1"', FieldComparison(Field("num"), Number(1)), schema=schema)

        self.validate('text:1', FieldComparison(Field("text"), String("1")), schema=schema)
        self.validate('text:"1"', FieldComparison(Field("text"), String("1")), schema=schema)

    def test_list_equals(self):
        self.assertEqual(kql.parse("a:(1 or 2)", optimize=False), kql.parse("a:(2 or 1)", optimize=False))

    def test_number_exists(self):
        self.assertEqual(kql.parse("foo:*", schema={"foo": "long"}), FieldComparison(Field("foo"), Exists()))

    def test_number_wildcard_fail(self):
        with self.assertRaises(kql.KqlParseError):
            kql.parse("foo:*wc", schema={"foo": "long"})

        with self.assertRaises(kql.KqlParseError):
            kql.parse("foo:wc*", schema={"foo": "long"})

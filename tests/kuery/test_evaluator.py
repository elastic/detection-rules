# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import unittest

import kql

document = {
    "number": 1,
    "boolean": True,
    "ip": "192.168.16.3",
    "string": "hello world",
    "string_list": ["hello world", "example"],
    "number_list": [1, 2, 3],
    "boolean_list": [True, False],
    "structured": [{"a": [{"b": 1}]}],
}


class EvaluatorTests(unittest.TestCase):
    def evaluate(self, source_text):
        evaluator = kql.get_evaluator(source_text, optimize=False)
        return evaluator(document)

    def test_single_value(self):
        self.assertTrue(self.evaluate("number:1"))
        self.assertTrue(self.evaluate('number:"1"'))
        self.assertTrue(self.evaluate("boolean:true"))
        self.assertTrue(self.evaluate('string:"hello world"'))

        self.assertFalse(self.evaluate("number:0"))
        self.assertFalse(self.evaluate("boolean:false"))
        self.assertFalse(self.evaluate('string:"missing"'))

    def test_list_value(self):
        self.assertTrue(self.evaluate("number_list:1"))
        self.assertTrue(self.evaluate("number_list:2"))
        self.assertTrue(self.evaluate("number_list:3"))

        self.assertTrue(self.evaluate("boolean_list:true"))
        self.assertTrue(self.evaluate("boolean_list:false"))

        self.assertTrue(self.evaluate('string_list:"hello world"'))
        self.assertTrue(self.evaluate("string_list:example"))

        self.assertFalse(self.evaluate("number_list:4"))
        self.assertFalse(self.evaluate('string_list:"missing"'))

    def test_and_values(self):
        self.assertTrue(self.evaluate("number_list:(1 and 2)"))
        self.assertTrue(self.evaluate("boolean_list:(false and true)"))
        self.assertFalse(self.evaluate('string:("missing" and "hello world")'))

        self.assertFalse(self.evaluate("number:(0 and 1)"))
        self.assertFalse(self.evaluate("boolean:(false and true)"))

    def test_not_value(self):
        self.assertTrue(self.evaluate("number_list:1"))
        self.assertFalse(self.evaluate("not number_list:1"))
        self.assertFalse(self.evaluate("number_list:(not 1)"))

    def test_or_values(self):
        self.assertTrue(self.evaluate("number:(0 or 1)"))
        self.assertTrue(self.evaluate("number:(1 or 2)"))
        self.assertTrue(self.evaluate("boolean:(false or true)"))
        self.assertTrue(self.evaluate('string:("missing" or "hello world")'))

        self.assertFalse(self.evaluate("number:(0 or 3)"))

    def test_and_expr(self):
        self.assertTrue(self.evaluate("number:1 and boolean:true"))

        self.assertFalse(self.evaluate("number:1 and boolean:false"))

    def test_or_expr(self):
        self.assertTrue(self.evaluate("number:1 or boolean:false"))
        self.assertFalse(self.evaluate("number:0 or boolean:false"))

    def test_range(self):
        self.assertTrue(self.evaluate("number < 2"))
        self.assertFalse(self.evaluate("number > 2"))

    def test_cidr_match(self):
        self.assertTrue(self.evaluate("ip:192.168.0.0/16"))

        self.assertFalse(self.evaluate("ip:10.0.0.0/8"))

    def test_quoted_wildcard(self):
        self.assertFalse(self.evaluate("string:'*'"))
        self.assertFalse(self.evaluate("string:'?'"))

    def test_wildcard(self):
        self.assertTrue(self.evaluate("string:hello*"))
        self.assertTrue(self.evaluate("string:*world"))
        self.assertFalse(self.evaluate("string:foobar*"))

    def test_field_exists(self):
        self.assertTrue(self.evaluate("number:*"))
        self.assertTrue(self.evaluate("boolean:*"))
        self.assertTrue(self.evaluate("ip:*"))
        self.assertTrue(self.evaluate("string:*"))
        self.assertTrue(self.evaluate("string_list:*"))
        self.assertTrue(self.evaluate("number_list:*"))
        self.assertTrue(self.evaluate("boolean_list:*"))

        self.assertFalse(self.evaluate("a:*"))

    def test_flattening(self):
        self.assertTrue(self.evaluate("structured.a.b:*"))
        self.assertTrue(self.evaluate("structured.a.b:1"))
        self.assertFalse(self.evaluate("structured.a.b:2"))

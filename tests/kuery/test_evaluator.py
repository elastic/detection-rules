# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import kql

class TestEvaluator:
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

    def evaluate(self, source_text, document=None):
        if document is None:
            document = self.document

        evaluator = kql.get_evaluator(source_text, optimize=False)
        return evaluator(document)

    def test_single_value(self):
        assert self.evaluate('number:1')
        assert self.evaluate('number:"1"')
        assert self.evaluate('boolean:true')
        assert self.evaluate('string:"hello world"')

        assert not self.evaluate('number:0')
        assert not self.evaluate('boolean:false')
        assert not self.evaluate('string:"missing"')

    def test_list_value(self):
        assert self.evaluate('number_list:1')
        assert self.evaluate('number_list:2')
        assert self.evaluate('number_list:3')

        assert self.evaluate('boolean_list:true')
        assert self.evaluate('boolean_list:false')

        assert self.evaluate('string_list:"hello world"')
        assert self.evaluate('string_list:example')

        assert not self.evaluate('number_list:4')
        assert not self.evaluate('string_list:"missing"')

    def test_and_values(self):
        assert self.evaluate('number_list:(1 and 2)')
        assert self.evaluate('boolean_list:(false and true)')
        assert not self.evaluate('string:("missing" and "hello world")')

        assert not self.evaluate('number:(0 and 1)')
        assert not self.evaluate('boolean:(false and true)')

    def test_not_value(self):
        assert self.evaluate('number_list:1')
        assert not self.evaluate('not number_list:1')
        assert not self.evaluate('number_list:(not 1)')

    def test_or_values(self):
        assert self.evaluate('number:(0 or 1)')
        assert self.evaluate('number:(1 or 2)')
        assert self.evaluate('boolean:(false or true)')
        assert self.evaluate('string:("missing" or "hello world")')

        assert not self.evaluate('number:(0 or 3)')

    def test_and_expr(self):
        assert self.evaluate('number:1 and boolean:true')
        assert not self.evaluate('number:1 and boolean:false')

    def test_or_expr(self):
        assert self.evaluate('number:1 or boolean:false')
        assert not self.evaluate('number:0 or boolean:false')

    def test_range(self):
        assert self.evaluate('number < 2')
        assert not self.evaluate('number > 2')

    def test_cidr_match(self):
        assert self.evaluate('ip:192.168.0.0/16')
        assert not self.evaluate('ip:10.0.0.0/8')

    def test_quoted_wildcard(self):
        assert not self.evaluate("string:'*'")
        assert not self.evaluate("string:'?'")

    def test_wildcard(self):
        assert self.evaluate('string:hello*')
        assert self.evaluate('string:*world')
        assert not self.evaluate('string:foobar*')

    def test_field_exists(self):
        assert self.evaluate('number:*')
        assert self.evaluate('boolean:*')
        assert self.evaluate('ip:*')
        assert self.evaluate('string:*')
        assert self.evaluate('string_list:*')
        assert self.evaluate('number_list:*')
        assert self.evaluate('boolean_list:*')

        assert not self.evaluate('a:*')

    def test_flattening(self):
        assert self.evaluate("structured.a.b:*")
        assert self.evaluate("structured.a.b:1")
        assert not self.evaluate("structured.a.b:2")

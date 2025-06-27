# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import unittest

import eql
import kql


class TestKql2Eql(unittest.TestCase):
    def validate(self, kql_source, eql_source, schema=None):
        self.assertEqual(kql.to_eql(kql_source, schema=schema), eql.parse_expression(eql_source))

    def test_field_equals(self):
        self.validate("field:value", "field == 'value'")
        self.validate("field:-1", "field == -1")
        self.validate("field:1.0", "field == 1.0")
        self.validate("field:true", "field == true")
        self.validate("field:false", "field == false")
        self.validate("not field:*", "field == null")
        self.validate("field:*", "field != null")

    def test_field_inequality(self):
        self.validate("field < value", "field < 'value'")
        self.validate("field > -1", "field > -1")
        self.validate("field <= 1.0", "field <= 1.0")
        self.validate("field >= 0", "field >= 0")

    def test_or_query(self):
        self.validate("field:value or field2:value2", "field == 'value' or field2 == 'value2'")

    def test_and_query(self):
        self.validate("field:value and field2:value2", "field == 'value' and field2 == 'value2'")

    def test_nested_query(self):
        with self.assertRaisesRegex(kql.KqlParseError, "Unable to convert nested query to EQL"):
            kql.to_eql("field:{outer:1 and middle:{inner:2}}")

    def test_not_query(self):
        self.validate("not field:value", "field != 'value'")
        self.validate("not (field:value and field2:value2)", "not (field = 'value' and field2 = 'value2')")

    def test_boolean_precedence(self):
        self.validate("a:1 or (b:2 and c:3)", "a == 1 or (b == 2 and c == 3)")
        self.validate("a:1 or b:2 and c:3", "a == 1 or (b == 2 and c == 3)")
        self.validate("a:1 or not b:2 and c:3", "a == 1 or (b != 2 and c == 3)")

    def test_list_of_values(self):
        self.validate("a:(0 or 1 or 2 or 3)", "a in (0,1,2,3)")
        self.validate("a:(0 or 1 and 2 or 3)", "a == 0 or a == 1 and a == 2 or a == 3")
        self.validate("a:(0 or 1 and 2 or (3 and 4))", "a == 0 or a == 1 and a == 2 or (a == 3 and a == 4)")

    def test_lone_value(self):
        for value in ["1", "-1.4", "true", '"string test"']:
            with self.assertRaisesRegex(kql.KqlParseError, "Value not tied to field"):
                kql.to_eql(value)

    def test_schema(self):
        schema = {
            "top": "nested",
            "top.keyword": "keyword",
            "top.text": "text",
            "top.middle": "nested",
            "top.middle.bool": "boolean",
            "top.numL": "long",
            "top.numF": "long",
            "dest": "ip",
        }

        self.validate("top.numF : 1", "top.numF == 1", schema=schema)
        self.validate('top.numF : "1"', "top.numF == 1", schema=schema)
        self.validate("top.keyword : 1", "top.keyword == '1'", schema=schema)
        self.validate('top.keyword : "hello"', "top.keyword == 'hello'", schema=schema)
        self.validate("dest:192.168.255.255", "dest == '192.168.255.255'", schema=schema)
        self.validate("dest:192.168.0.0/16", "cidrMatch(dest, '192.168.0.0/16')", schema=schema)
        self.validate('dest:"192.168.0.0/16"', "cidrMatch(dest, '192.168.0.0/16')", schema=schema)

        with self.assertRaises(eql.EqlSemanticError):
            self.validate('top.text : "hello"', "top.text == 'hello'", schema=schema)

        with self.assertRaises(eql.EqlSemanticError):
            self.validate("top.text : 1 ", "top.text == '1'", schema=schema)

        with self.assertRaisesRegex(kql.KqlParseError, r"Value doesn't match top.middle's type: nested"):
            kql.to_eql("top.middle : 1", schema=schema)

        with self.assertRaisesRegex(kql.KqlParseError, "Unable to convert nested query to EQL"):
            kql.to_eql("top:{keyword : 1}", schema=schema)

        with self.assertRaisesRegex(kql.KqlParseError, "Unable to convert nested query to EQL"):
            kql.to_eql("top:{middle:{bool: true}}", schema=schema)

        invalid_ips = ["192.168.0.256", "192.168.0.256/33", "1", '"1"']
        for ip in invalid_ips:
            with self.assertRaisesRegex(kql.KqlParseError, r"Value doesn't match dest's type: ip"):
                kql.to_eql(f"dest:{ip}", schema=schema)

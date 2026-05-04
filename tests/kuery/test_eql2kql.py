# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import unittest

import eql
import kql


class TestEql2Kql(unittest.TestCase):
    def validate(self, kql_source, eql_source):
        self.assertEqual(kql_source, str(kql.from_eql(eql_source)))

    def test_field_equals(self):
        self.validate("field:value", "field == 'value'")
        self.validate("field:-1", "field == -1")
        self.validate("field:1.1", "field == 1.1")
        self.validate("field:true", "field == true")
        self.validate("field:false", "field == false")
        self.validate("field:*", "field != null")
        self.validate("not field:*", "field == null")

    def test_field_inequality(self):
        self.validate("field < value", "field < 'value'")
        self.validate("field > -1", "field > -1")
        self.validate("field <= 1.1", "field <= 1.1")
        self.validate("field >= 0", "field >= 0")

    def test_or_query(self):
        self.validate("field:value or field2:value2", "field == 'value' or field2 == 'value2'")

    def test_and_query(self):
        self.validate("field:value and field2:value2", "field == 'value' and field2 == 'value2'")

    def test_not_query(self):
        self.validate("not field:value", "field != 'value'")
        self.validate("not (field:value and field2:value2)", "not (field = 'value' and field2 = 'value2')")

    def test_boolean_precedence(self):
        self.validate("a:1 or b:2 and c:3", "a == 1 or (b == 2 and c == 3)")
        self.validate("a:1 and (b:2 or c:3)", "a == 1 and (b == 2 or c == 3)")
        self.validate("a:1 or not b:2 and c:3", "a == 1 or (b != 2 and c == 3)")

    def test_list_of_values(self):
        self.validate("a:(0 or 1 or 2 or 3)", "a in (0,1,2,3)")
        self.validate("a:(0 or 3 or 1 and 2)", "a == 0 or a == 1 and a == 2 or a == 3")
        self.validate("a:(0 or 1 and 2 or 3 and 4)", "a == 0 or a == 1 and a == 2 or (a == 3 and a == 4)")

    def test_ip_checks(self):
        self.validate("dest:192.168.255.255", "dest == '192.168.255.255'")
        self.validate("dest:192.168.0.0/16", "cidrMatch(dest, '192.168.0.0/16')")
        self.validate("dest:192.168.0.0/16", "cidrMatch(dest, '192.168.0.0/16')")

    def test_wildcard_field(self):
        with eql.parser.elasticsearch_validate_optional_fields:
            self.validate("field:value-*", 'field : "value-*"')
            self.validate("field:value-?", 'field : "value-?"')

        with eql.parser.elasticsearch_validate_optional_fields, self.assertRaises(AssertionError):
            self.validate('field:"value-*"', 'field == "value-*"')
            self.validate('field:"value-?"', 'field == "value-?"')

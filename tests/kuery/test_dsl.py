# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import unittest

import kql


class TestKQLtoDSL(unittest.TestCase):
    def validate(self, kql_source, dsl, **kwargs):
        actual_dsl = kql.to_dsl(kql_source, **kwargs)
        self.assertListEqual(list(actual_dsl), ["bool"])
        self.assertDictEqual(actual_dsl["bool"], dsl)

    def test_field_match(self):
        def match(**kv):
            return {"filter": [{"match": kv}]}

        self.validate("user:bob", match(user="bob"))
        self.validate("number:-1", match(number=-1))
        self.validate("number:1.1", match(number=1.1))
        self.validate("boolean:true", match(boolean=True))
        self.validate("boolean:false", match(boolean=False))

    def test_field_exists(self):
        self.validate("user:*", {"filter": [{"exists": {"field": "user"}}]})

    def test_field_inequality(self):
        def rng(op, val):
            return {"filter": [{"range": {"field": {op: val}}}]}

        self.validate("field < value", rng("lt", "value"))
        self.validate("field > -1", rng("gt", -1))
        self.validate("field <= 1.1", rng("lte", 1.1))
        self.validate("field >= 0", rng("gte", 0))
        self.validate("field >= abc", rng("gte", "abc"))

    def test_or_query(self):
        self.validate(
            "field:value or field2:value2",
            {"should": [{"match": {"field": "value"}}, {"match": {"field2": "value2"}}], "minimum_should_match": 1},
        )

    def test_and_query(self):
        self.validate(
            "field:value and field2:value2",
            {"filter": [{"match": {"field": "value"}}, {"match": {"field2": "value2"}}]},
        )

    def test_not_query(self):
        self.validate("not field:value", {"must_not": [{"match": {"field": "value"}}]})
        self.validate("field:(not value)", {"must_not": [{"match": {"field": "value"}}]})
        self.validate(
            "field:(a and not b)", {"filter": [{"match": {"field": "a"}}], "must_not": [{"match": {"field": "b"}}]}
        )
        self.validate(
            "not field:value and not field2:value2",
            {"must_not": [{"match": {"field": "value"}}, {"match": {"field2": "value2"}}]},
        )
        self.validate(
            "not (field:value or field2:value2)",
            {
                "must_not": [
                    {
                        "bool": {
                            "minimum_should_match": 1,
                            "should": [{"match": {"field": "value"}}, {"match": {"field2": "value2"}}],
                        }
                    }
                ]
            },
            optimize=False,
        )

        self.validate(
            "not (field:value and field2:value2)",
            {"must_not": [{"bool": {"filter": [{"match": {"field": "value"}}, {"match": {"field2": "value2"}}]}}]},
        )

    def test_optimizations(self):
        self.validate(
            "(field:value or field2:value2) and field3:value3",
            {
                "should": [{"match": {"field": "value"}}, {"match": {"field2": "value2"}}],
                "filter": [{"match": {"field3": "value3"}}],
                "minimum_should_match": 1,
            },
        )

        self.validate(
            "(field:value and field2:value2) or field3:value3",
            {
                "should": [
                    {"bool": {"filter": [{"match": {"field": "value"}}, {"match": {"field2": "value2"}}]}},
                    {"match": {"field3": "value3"}},
                ],
                "minimum_should_match": 1,
            },
        )

        self.validate(
            "a:(v1 or v2 or v3) or b:(v4 or v5)",
            {
                "should": [
                    {"match": {"a": "v1"}},
                    {"match": {"a": "v2"}},
                    {"match": {"a": "v3"}},
                    {"match": {"b": "v4"}},
                    {"match": {"b": "v5"}},
                ],
                "minimum_should_match": 1,
            },
        )

        self.validate(
            "a:(v1 or v2 or v3) and b:(v4 or v5)",
            {
                "should": [{"match": {"a": "v1"}}, {"match": {"a": "v2"}}, {"match": {"a": "v3"}}],
                "filter": [
                    {"bool": {"should": [{"match": {"b": "v4"}}, {"match": {"b": "v5"}}], "minimum_should_match": 1}}
                ],
                "minimum_should_match": 1,
            },
        )

        self.validate(
            "(field:value and not field2:value2) or field3:value3",
            {
                "should": [
                    {
                        "bool": {
                            "filter": [{"match": {"field": "value"}}],
                            "must_not": [{"match": {"field2": "value2"}}],
                        }
                    },
                    {"match": {"field3": "value3"}},
                ],
                "minimum_should_match": 1,
            },
        )

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Tests for the python-esql backed ES|QL validation."""

import unittest

from detection_rules.esql_errors import (
    EsqlSchemaError,
    EsqlSemanticError,
    EsqlSyntaxError,
    EsqlTypeMismatchError,
)
from detection_rules.index_mappings import execute_query_against_indices, get_query_columns


def _log(_: str) -> None:
    """No-op logger for tests."""


MAPPING = {
    "logs-test-*": {
        "properties": {
            "foo": {"type": "integer"},
            "name": {"type": "keyword"},
            "event": {"properties": {"category": {"type": "keyword"}}},
        }
    }
}


class TestEsqlLocalValidation(unittest.TestCase):
    """End-to-end checks of the python-esql local validation path."""

    def test_valid_query_returns_columns(self) -> None:
        """A well-formed query returns the referenced columns with schema types."""
        columns, response = execute_query_against_indices(
            None,
            "FROM logs-test-* | WHERE foo == 1 | LIMIT 5",
            MAPPING,
            _log,
        )
        self.assertEqual(response, {"columns": columns})
        self.assertIn({"name": "foo", "type": "integer"}, columns)

    def test_syntax_error(self) -> None:
        """Invalid ES|QL syntax raises the detection-rules EsqlSyntaxError."""
        with self.assertRaises(EsqlSyntaxError):
            _ = execute_query_against_indices(None, "FROM logs-test-* | WAT", MAPPING, _log)

    def test_unknown_field_is_schema_error(self) -> None:
        """References to fields missing from the supplied mapping raise EsqlSchemaError."""
        with self.assertRaises(EsqlSchemaError) as ctx:
            _ = execute_query_against_indices(None, "FROM logs-test-* | WHERE missing_field == 1", MAPPING, _log)
        self.assertIn("missing_field", str(ctx.exception))

    def test_type_mismatch_error(self) -> None:
        """Ordering a keyword field against a number is flagged as a type mismatch."""
        with self.assertRaises(EsqlTypeMismatchError):
            _ = execute_query_against_indices(None, "FROM logs-test-* | WHERE name > 1", MAPPING, _log)

    def test_eval_defined_columns_are_returned(self) -> None:
        """Pipeline-defined columns (EVAL/STATS) appear in the returned columns."""
        columns, _ = execute_query_against_indices(
            None,
            "FROM logs-test-* | EVAL Esql.foo_doubled = foo * 2 | STATS Esql.foo_count = count(*) BY event.category",
            MAPPING,
            _log,
        )
        names = [c["name"] for c in columns]
        self.assertIn("Esql.foo_doubled", names)
        self.assertIn("Esql.foo_count", names)
        self.assertIn("event.category", names)

    def test_nested_kql_is_validated(self) -> None:
        """Invalid nested KQL payloads are surfaced as semantic errors."""
        with self.assertRaises(EsqlSemanticError):
            _ = execute_query_against_indices(
                None,
                'FROM logs-test-* | WHERE KQL("event.category : ") | LIMIT 5',
                MAPPING,
                _log,
            )

    def test_multi_pattern_mappings_are_unioned(self) -> None:
        """Fields are resolved across all supplied index patterns."""
        indices = {
            "logs-a-*": {"properties": {"alpha": {"type": "keyword"}}},
            "logs-b-*": {"properties": {"beta": {"type": "long"}}},
        }
        columns, _ = execute_query_against_indices(
            None,
            'FROM logs-a-*,logs-b-* | WHERE alpha == "x" AND beta > 0',
            indices,
            _log,
        )
        names = [c["name"] for c in columns]
        self.assertIn("alpha", names)
        self.assertIn("beta", names)

    def test_comma_joined_pattern_key(self) -> None:
        """The comma-joined pattern key produced by remote_validate_rule resolves fields."""
        indices = {"logs-a-*,logs-b-*": {"properties": {"alpha": {"type": "keyword"}}}}
        columns, _ = execute_query_against_indices(
            None,
            'FROM logs-a-*,logs-b-* | WHERE alpha == "x"',
            indices,
            _log,
        )
        self.assertIn({"name": "alpha", "type": "keyword"}, columns)

    def test_min_stack_version_gates_syntax(self) -> None:
        """Newer-stack-only syntax parses on a new stack version."""
        columns, _ = execute_query_against_indices(
            None,
            "FROM logs-test-* | WHERE foo == 1",
            MAPPING,
            _log,
            min_stack_version="9.5.0",
        )
        self.assertTrue(columns)

    def test_get_query_columns_types(self) -> None:
        """get_query_columns resolves types from the schema for referenced fields."""
        import esql

        schema = esql.Schema(MAPPING, allow_missing=False)
        with schema:
            tree = esql.parse_query('FROM logs-test-* | WHERE event.category == "process" AND foo == 1')
        columns = {c["name"]: c["type"] for c in get_query_columns(tree, schema)}
        self.assertEqual(columns.get("event.category"), "keyword")
        self.assertEqual(columns.get("foo"), "integer")

    def test_multiple_sequential_validations(self) -> None:
        """Validation stays healthy across many sequential calls."""
        for i in range(10):
            columns, _ = execute_query_against_indices(None, f"FROM logs-test-* | LIMIT {i + 1}", MAPPING, _log)
            self.assertIsInstance(columns, list)


if __name__ == "__main__":
    unittest.main()

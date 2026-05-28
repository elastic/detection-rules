# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Tests for the Java-backed ES|QL validator wrapper."""

import os
import unittest
from pathlib import Path

from detection_rules.esql_parser import EsqlValidator, ValidationError

VALIDATOR_DIR = Path(__file__).resolve().parents[1] / "lib" / "esql-validator"
JAR_PATH = VALIDATOR_DIR / "build" / "esql-validator.jar"
CLASSPATH_FILE = VALIDATOR_DIR / "build" / "classpath.txt"

# The Java daemon is heavy to build (requires an Elasticsearch checkout). We skip
# this test suite unless the JAR is already present, or DR_ESQL_BUILD=1 is set.
SHOULD_RUN = (JAR_PATH.exists() and CLASSPATH_FILE.exists()) or os.environ.get("DR_ESQL_BUILD") == "1"


@unittest.skipUnless(
    SHOULD_RUN,
    "esql-validator JAR not built. Run lib/esql-validator/build.sh or set DR_ESQL_BUILD=1.",
)
class TestEsqlValidator(unittest.TestCase):
    """End-to-end checks of the JVM daemon wrapper."""

    @classmethod
    def setUpClass(cls) -> None:
        """Spawn one JVM daemon and reuse it across every test method in the class."""
        cls.validator = EsqlValidator(build_if_missing=os.environ.get("DR_ESQL_BUILD") == "1")
        cls.validator.start()

    @classmethod
    def tearDownClass(cls) -> None:
        """Reap the JVM daemon after the last test runs."""
        cls.validator.stop()

    def test_ping(self) -> None:
        """Smoke-test the stdin/stdout JSON round-trip with a trivial query."""
        result = self.validator.validate("FROM idx", indices={"idx": {"properties": {"a": {"type": "long"}}}})
        self.assertEqual(result.status, "ok")

    def test_valid_query_returns_plan(self) -> None:
        """A well-formed query returns ok with a populated analyzed-plan text."""
        result = self.validator.validate(
            "FROM logs | WHERE foo == 1 | LIMIT 5",
            indices={"logs": {"properties": {"foo": {"type": "integer"}}}},
        )
        self.assertTrue(result.ok, msg=result.raw)
        self.assertIsNotNone(result.plan)
        self.assertIn("EsRelation[logs]", result.plan)

    def test_parse_error_includes_position(self) -> None:
        """Syntax errors surface as parse_error with structured line/column."""
        result = self.validator.validate("FROM logs | WAT")
        self.assertEqual(result.status, "parse_error")
        self.assertGreaterEqual(len(result.errors), 1)
        err = result.errors[0]
        self.assertEqual(err.type, "ParsingException")
        self.assertEqual(err.line, 1)
        self.assertGreater(err.column or 0, 0)

    def test_unknown_field_is_verify_error(self) -> None:
        """References to fields missing from the supplied mapping become verify_error."""
        result = self.validator.validate(
            "FROM logs | WHERE missing_field == 1",
            indices={"logs": {"properties": {"foo": {"type": "integer"}}}},
        )
        self.assertEqual(result.status, "verify_error")
        err = result.errors[0]
        self.assertEqual(err.type, "VerificationException")
        self.assertIn("missing_field", err.message)
        self.assertEqual(err.line, 1)

    def test_type_mismatch_is_verify_error(self) -> None:
        """Comparing a keyword field with a number is flagged by the Verifier."""
        result = self.validator.validate(
            'FROM logs | WHERE name == 1',
            indices={"logs": {"properties": {"name": {"type": "keyword"}}}},
        )
        self.assertEqual(result.status, "verify_error", msg=result.raw)
        self.assertTrue(any("name" in e.message for e in result.errors), msg=result.errors)

    def test_raise_for_status(self) -> None:
        """raise_for_status() turns any non-ok result into a ValidationError."""
        result = self.validator.validate("FROM x | WAT")
        with self.assertRaises(ValidationError):
            result.raise_for_status()

    def test_multiple_round_trips_share_daemon(self) -> None:
        """The long-running daemon stays healthy across many sequential calls."""
        mapping = {"logs": {"properties": {"foo": {"type": "integer"}}}}
        for i in range(10):
            r = self.validator.validate(f"FROM logs | LIMIT {i + 1}", indices=mapping)
            self.assertTrue(r.ok, msg=f"iteration {i}: {r.raw}")


if __name__ == "__main__":
    unittest.main()

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import unittest
from typing import Any

from detection_rules import ecs, endgame
from detection_rules.rule_validators import ValidationTarget, deduplicate_validation_targets


class TestValidationTargetDeduplication(unittest.TestCase):
    """Test that equivalent parser inputs are validated only once."""

    @staticmethod
    def make_target(schema: Any, **overrides: Any) -> ValidationTarget:
        values: dict[str, Any] = {
            "query_text": "process where true",
            "schema": schema,
            "err_trailer": "stack: 9.6.0",
            "min_stack_version": "8.19.0",
            "kind": "stack",
        }
        values.update(overrides)
        return ValidationTarget(**values)

    def test_equal_schemas_keep_the_first_target(self) -> None:
        fields = {"process.name": "keyword"}
        first = self.make_target(dict(fields), beat_types=["auditbeat"])
        duplicate = self.make_target(
            dict(fields),
            err_trailer="stack: 9.5.0",
            kind="integration",
            integration_types=["endpoint"],
        )

        result = deduplicate_validation_targets([first, duplicate])

        self.assertEqual(result, [first])

    def test_distinct_parser_inputs_are_retained(self) -> None:
        fields = {"process.name": "keyword"}
        targets = [
            self.make_target(dict(fields)),
            self.make_target({"user.name": "keyword"}),
            self.make_target(dict(fields), query_text="network where true"),
            self.make_target(dict(fields), min_stack_version="9.3.0"),
        ]

        self.assertEqual(deduplicate_validation_targets(targets), targets)

    def test_wrapped_schemas_deduplicate_only_with_the_same_type(self) -> None:
        fields = {"process.name": "keyword"}
        first = self.make_target(ecs.KqlSchema2Eql(dict(fields)))
        duplicate = self.make_target(ecs.KqlSchema2Eql(dict(fields)))
        endgame_target = self.make_target(endgame.EndgameSchema(dict(fields)))

        result = deduplicate_validation_targets([first, duplicate, endgame_target])

        self.assertEqual(result, [first, endgame_target])

    def test_unknown_schema_shapes_are_retained(self) -> None:
        first = self.make_target(object())
        second = self.make_target(object())

        self.assertEqual(deduplicate_validation_targets([first, second]), [first, second])

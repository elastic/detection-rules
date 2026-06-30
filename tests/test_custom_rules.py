# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Tests for custom rules helpers."""

import unittest

from detection_rules.custom_rules import get_stack_schema_map_entry_for_version


class TestCustomRulesSetupConfig(unittest.TestCase):
    """Test custom rules setup config helpers."""

    def test_stack_schema_map_entry_matches_requested_package_version(self):
        """The generated custom config must align package name and stack schema map."""
        stack_schema_map = {
            "9.3.0": {"beats": "9.3.3", "ecs": "9.3.0", "endgame": "8.4.0"},
            "9.5.0": {"beats": "9.3.4", "ecs": "9.4.0-rc1", "endgame": "8.4.0"},
        }

        self.assertEqual(
            get_stack_schema_map_entry_for_version(stack_schema_map, "9.3"),
            {"9.3.0": stack_schema_map["9.3.0"]},
        )

    def test_stack_schema_map_entry_raises_for_unsupported_package_version(self):
        """Unsupported custom package versions should fail with a clear error."""
        stack_schema_map = {"9.5.0": {"beats": "9.3.4", "ecs": "9.4.0-rc1", "endgame": "8.4.0"}}

        with self.assertRaisesRegex(ValueError, "No stack-schema-map entry found"):
            _ = get_stack_schema_map_entry_for_version(stack_schema_map, "9.3")

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test immutable rule fields (immutable, rule_source, version, revision) in TOML export/import."""

import unittest
from pathlib import Path

import pytoml

from detection_rules.rule_loader import RuleCollection

# Valid ESQL query with metadata and keep so load_dict passes validation
VALID_ESQL_QUERY = """
FROM logs-windows.powershell_operational* METADATA _id, _version, _index
| WHERE event.code == "4104"
| KEEP event.code, _id, _version, _index
"""


def _load_rule_dict_with_immutable_fields(rule_path: Path, immutable: bool = True, **kwargs) -> dict:
    """Load rule dict from TOML and set valid ESQL query plus immutable-related fields."""
    rule_body = rule_path.read_text()
    rule_dict = pytoml.loads(rule_body)
    rule_dict["rule"]["query"] = VALID_ESQL_QUERY.strip()
    rule_dict["rule"]["immutable"] = immutable
    rule_dict["rule"]["rule_source"] = kwargs.get(
        "rule_source",
        {"type": "external", "is_customized": False, "customized_fields": [], "has_base_version": True},
    )
    rule_dict["rule"]["version"] = kwargs.get("version", 107)
    rule_dict["rule"]["revision"] = kwargs.get("revision", 0)
    return rule_dict


class TestImmutableRuleFields(unittest.TestCase):
    """Round-trip and export of immutable rule fields."""

    def test_to_api_format_includes_immutable_fields_when_present(self):
        """When a rule has immutable, rule_source, version, revision in TOML, to_api_format() includes them."""
        rule_path = Path("tests/data/command_control_dummy_production_rule.toml")
        rule_dict = _load_rule_dict_with_immutable_fields(rule_path)

        rc = RuleCollection()
        rule = rc.load_dict(rule_dict, path=rule_path)
        api = rule.contents.to_api_format(include_version=True)

        self.assertTrue(api.get("immutable") is True)
        self.assertEqual(
            api.get("rule_source"),
            {
                "type": "external",
                "is_customized": False,
                "customized_fields": [],
                "has_base_version": True,
            },
        )
        self.assertEqual(api.get("version"), 107)
        self.assertEqual(api.get("revision"), 0)

    def test_to_api_format_includes_customized_rule_source(self):
        """When a rule has customized rule_source, to_api_format() preserves customized_fields."""
        rule_path = Path("tests/data/command_control_dummy_production_rule.toml")
        rule_dict = _load_rule_dict_with_immutable_fields(
            rule_path,
            rule_source={
                "type": "external",
                "is_customized": True,
                "customized_fields": [
                    {"field_name": "tags"},
                    {"field_name": "query"},
                ],
                "has_base_version": True,
            },
            version=3,
            revision=5,
        )

        rc = RuleCollection()
        rule = rc.load_dict(rule_dict, path=rule_path)
        api = rule.contents.to_api_format(include_version=True)

        self.assertEqual(api.get("version"), 3)
        self.assertEqual(api.get("revision"), 5)
        self.assertEqual(api["rule_source"]["is_customized"], True)
        self.assertEqual(
            [f["field_name"] for f in api["rule_source"]["customized_fields"]],
            ["tags", "query"],
        )

    def test_round_trip_immutable_fields_via_to_dict(self):
        """Rule with immutable fields survives to_dict -> from_dict and to_api_format still has them."""
        rule_path = Path("tests/data/command_control_dummy_production_rule.toml")
        rule_dict = _load_rule_dict_with_immutable_fields(rule_path, version=42, revision=1)

        rc = RuleCollection()
        rule = rc.load_dict(rule_dict, path=rule_path)
        # Round-trip through to_dict (as when saving TOML) and back
        from detection_rules.rule import TOMLRuleContents

        round_trip_contents = TOMLRuleContents.from_dict(rule.contents.to_dict())
        api = round_trip_contents.to_api_format(include_version=True)

        self.assertTrue(api.get("immutable") is True)
        self.assertEqual(api["rule_source"]["type"], "external")
        self.assertEqual(api.get("version"), 42)
        self.assertEqual(api.get("revision"), 1)

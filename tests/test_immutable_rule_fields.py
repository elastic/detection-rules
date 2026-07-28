# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test prebuilt rule fields (immutable, rule_source, version, revision) in TOML export/import."""

import unittest
from typing import Any

from detection_rules.cli_utils import rule_prompt
from detection_rules.rule import TOMLRule, TOMLRuleContents
from detection_rules.utils import get_path

DEFAULT_RULE_SOURCE = {
    "type": "external",
    "is_customized": False,
    "customized_fields": [],
    "has_base_version": True,
}


def build_rule_resource(
    immutable: bool = True,
    version: int = 107,
    revision: int = 2,
    rule_source: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a rule resource mimicking what `kibana export-rules` returns for a prebuilt rule.

    Uses a KQL query rule so the test does not depend on a live Kibana cluster for validation.
    """
    resource = {
        "id": "9cda25df-2fd0-4969-9671-17532a494614",
        "rule_id": "34fde489-94b0-4500-a76f-b8a157cf9269",
        "name": "Accepted Default Telnet Port Connection",
        "description": "Sample prebuilt rule for unit tests.",
        "author": ["Elastic"],
        "license": "Elastic License v2",
        "risk_score": 47,
        "severity": "medium",
        "type": "query",
        "language": "kuery",
        "index": ["logs-endpoint.events.network-*"],
        "query": "destination.port:23 and network.transport:tcp",
        "tags": ["Domain: Endpoint"],
        "from": "now-9m",
        "to": "now",
        "interval": "5m",
        "max_signals": 100,
        "enabled": False,
        "setup": "",
        "investigation_fields": None,
        "related_integrations": [],
        "required_fields": [],
        "threat": [],
        "immutable": immutable,
        "rule_source": rule_source or DEFAULT_RULE_SOURCE,
        "version": version,
        "revision": revision,
    }

    if not immutable:
        # The schema only permits version and revision on prebuilt rules.
        del resource["version"]
        del resource["revision"]

    return resource


class TestImmutableRuleFields(unittest.TestCase):
    """Round-trip and export of prebuilt rule fields."""

    def test_to_api_format_includes_prebuilt_fields(self):
        """A prebuilt rule exports immutable, rule_source, version and revision to the API format."""
        contents = TOMLRuleContents.from_rule_resource(build_rule_resource())
        api = contents.to_api_format(include_version=True)

        self.assertIs(api.get("immutable"), True)
        self.assertEqual(api.get("rule_source"), DEFAULT_RULE_SOURCE)
        self.assertEqual(api.get("version"), 107)
        self.assertEqual(api.get("revision"), 2)

    def test_to_api_format_preserves_customized_rule_source(self):
        """Customization tracking in rule_source survives the export."""
        contents = TOMLRuleContents.from_rule_resource(
            build_rule_resource(
                version=3,
                revision=5,
                rule_source={
                    "type": "external",
                    "is_customized": True,
                    "customized_fields": [{"field_name": "tags"}, {"field_name": "query"}],
                    "has_base_version": True,
                },
            )
        )
        api = contents.to_api_format(include_version=True)

        self.assertEqual(api.get("version"), 3)
        self.assertEqual(api.get("revision"), 5)
        self.assertIs(api["rule_source"]["is_customized"], True)
        self.assertEqual([f["field_name"] for f in api["rule_source"]["customized_fields"]], ["tags", "query"])

    def test_round_trip_through_toml_dict(self):
        """Prebuilt fields survive the to_dict/from_dict round trip used when saving TOML."""
        contents = TOMLRuleContents.from_rule_resource(build_rule_resource(version=42, revision=1))

        rule_dict = contents.to_dict()
        self.assertIs(rule_dict["rule"].get("immutable"), True)
        self.assertEqual(rule_dict["rule"].get("version"), 42)
        self.assertEqual(rule_dict["rule"].get("revision"), 1)

        api = TOMLRuleContents.from_dict(rule_dict).to_api_format(include_version=True)
        self.assertIs(api.get("immutable"), True)
        self.assertEqual(api["rule_source"]["type"], "external")
        self.assertEqual(api.get("version"), 42)
        self.assertEqual(api.get("revision"), 1)

    def test_custom_rule_still_uses_version_lock(self):
        """Rules that are not prebuilt keep using the version lock, and can omit the version."""
        contents = TOMLRuleContents.from_rule_resource(build_rule_resource(immutable=False))

        self.assertNotIn("version", contents.to_api_format(include_version=False))

        api = contents.to_api_format(include_version=True)
        self.assertEqual(api.get("version"), contents.autobumped_version)
        self.assertNotIn("revision", api)

    def test_rule_prompt_preserves_prebuilt_fields(self):
        """Regression test for the `import-rules-to-repo` path.

        `immutable` is popped off kwargs before `revision` and `version` are reached, so a
        naive `kwargs.get("immutable")` check silently drops the cluster-assigned versions.
        """
        resource = build_rule_resource(version=111, revision=2)
        # Mirror how main.import_rules_into_repo builds the additional required fields.
        additional = ["index"] + [key for key in resource if key != "index" and resource.get(key)]

        rule = rule_prompt(
            get_path(["tests", "data", "command_control_dummy_production_rule.toml"]),
            required_only=True,
            save=False,
            additional_required=additional,
            skip_errors=True,
            **resource,
        )

        self.assertIsInstance(rule, TOMLRule, msg=f"rule_prompt failed: {rule}")
        assert isinstance(rule, TOMLRule)

        toml_rule = rule.contents.to_dict()["rule"]
        self.assertIs(toml_rule.get("immutable"), True)
        self.assertEqual(toml_rule.get("version"), 111)
        self.assertEqual(toml_rule.get("revision"), 2)
        self.assertEqual(toml_rule.get("rule_source", {}).get("type"), "external")

        api = rule.contents.to_api_format(include_version=True)
        self.assertIs(api.get("immutable"), True)
        self.assertEqual(api.get("version"), 111)
        self.assertEqual(api.get("revision"), 2)

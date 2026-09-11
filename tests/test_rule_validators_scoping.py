# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test that integration validation targets use the package field schema without the full ECS schema."""

import unittest
import unittest.mock
from types import SimpleNamespace

from semver import Version

from detection_rules.config import load_current_package_version
from detection_rules.rule_validators import INTEGRATION_SCHEMA_HINT, KQLValidator, ValidationTarget
from detection_rules.schemas import get_stack_schemas

PACKAGE = "network_traffic"
INTEGRATION = "icmp"
INDEX = f"logs-{PACKAGE}.{INTEGRATION}-*"
# process.title is a valid ECS field the data stream does not declare
QUERY = f'data_stream.dataset:{PACKAGE}.{INTEGRATION} and destination.ip:10.0.0.0/8 and process.title:"test"'


def _manifests() -> dict:
    current_major = Version.parse(load_current_package_version(), optional_minor_and_patch=True).major
    return {PACKAGE: {"1.0.0": {"conditions": {"kibana": {"version": f"^{current_major}.0.0"}}}}}


def _schemas() -> dict:
    """Cached package schema for a single data stream."""
    data_stream = {
        "data_stream.dataset": "constant_keyword",
        "destination.ip": "ip",
        f"{PACKAGE}.{INTEGRATION}.request.type": "long",
    }
    return {PACKAGE: {"1.0.0": {INTEGRATION: data_stream}}}


def _build_plan(schemas: dict) -> list[ValidationTarget]:
    """Build a KQL validation plan against mocked integration manifests and schemas."""
    validator = KQLValidator(QUERY)
    current = load_current_package_version()
    data = SimpleNamespace(
        language="kuery",
        index=[INDEX],
        index_or_dataview=[INDEX],
        name="integration schema test rule",
        rule_id="00000000-0000-0000-0000-000000000000",
        ast=validator.ast,
        get=lambda key, default=None: {"ast": validator.ast, "notify": False}.get(key, default),
    )
    meta = SimpleNamespace(
        maturity="production",
        min_stack_version=current,
        integration=[PACKAGE],
        get=lambda key, default=None: {"integration": [PACKAGE]}.get(key, default),
        get_validation_stack_versions=lambda: get_stack_schemas(current),
    )
    manifests = _manifests()
    with (
        unittest.mock.patch("detection_rules.rule_validators.load_integrations_manifests", return_value=manifests),
        unittest.mock.patch("detection_rules.integrations.load_integrations_manifests", return_value=manifests),
        unittest.mock.patch("detection_rules.integrations.load_integrations_schemas", return_value=schemas),
        unittest.mock.patch("detection_rules.integrations.find_latest_integration_patch_for_minor", return_value=0),
    ):
        return validator.build_validation_plan(data, meta)  # type: ignore[reportArgumentType]


class TestKQLPlanIntegrationTargets(unittest.TestCase):
    """Integration targets exclude undeclared ECS fields and tell the author where populated fields belong."""

    def test_integration_target_uses_package_schema_and_hints(self):
        targets = [target for target in _build_plan(_schemas()) if target.kind == "integration"]
        self.assertTrue(targets, "expected at least one integration validation target")
        for target in targets:
            self.assertEqual(target.integration_types, [PACKAGE])
            # the schema behind the target excludes the undeclared ECS field
            self.assertNotIn("process.title", target.schema)
            self.assertIn("destination.ip", target.schema)
            # existing trailer lines are preserved and the hint names where to declare populated fields
            self.assertIn("Try adding event.module or event.dataset", target.err_trailer)
            self.assertIn(f"Checked against packages [{PACKAGE}]", target.err_trailer)
            self.assertIn(INTEGRATION_SCHEMA_HINT, target.err_trailer)
            self.assertIn("rule: integration schema test rule", target.err_trailer)

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test the ECS-scoping hint in query validation error trailers."""

import unittest
import unittest.mock
from types import SimpleNamespace

from semver import Version

from detection_rules.config import load_current_package_version
from detection_rules.rule_validators import KQLValidator, ValidationTarget, _scoped_trailer
from detection_rules.schemas import get_stack_schemas

PACKAGE = "network_traffic"
INTEGRATION = "icmp"
INDEX = f"logs-{PACKAGE}.{INTEGRATION}-*"
# process.title is a valid ECS field the data stream does not declare
QUERY = f'data_stream.dataset:{PACKAGE}.{INTEGRATION} and destination.ip:10.0.0.0/8 and process.title:"test"'


def _manifests() -> dict:
    current_major = Version.parse(load_current_package_version(), optional_minor_and_patch=True).major
    return {PACKAGE: {"1.0.0": {"conditions": {"kibana": {"version": f"^{current_major}.0.0"}}}}}


def _schemas(scoped: bool) -> dict:
    """Cached package schema for a single data stream, optionally flagged as ECS-scoped."""
    data_stream = {
        "data_stream.dataset": "constant_keyword",
        "destination.ip": "ip",
        f"{PACKAGE}.{INTEGRATION}.request.type": "long",
    }
    version_schema: dict = {INTEGRATION: data_stream}
    if scoped:
        version_schema["_meta"] = {"ecs_scoped": [INTEGRATION]}
    return {PACKAGE: {"1.0.0": version_schema}}


def _build_plan(schemas: dict) -> list[ValidationTarget]:
    """Build a KQL validation plan against mocked integration manifests and schemas."""
    validator = KQLValidator(QUERY)
    current = load_current_package_version()
    data = SimpleNamespace(
        language="kuery",
        index=[INDEX],
        index_or_dataview=[INDEX],
        name="scoping test rule",
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


class TestScopedTrailerHelper(unittest.TestCase):
    """The helper renders nothing for unscoped rows and a sorted package list otherwise."""

    def test_empty_when_no_scoped_packages(self):
        self.assertEqual(_scoped_trailer(set()), "")

    def test_lists_scoped_packages_sorted(self):
        trailer = _scoped_trailer({"zeek", "network_traffic"})
        self.assertIn("ECS-scoped packages [network_traffic, zeek]", trailer)
        self.assertIn("detection_rules/etc/non-ecs-schema.json", trailer)


class TestKQLPlanScopedTrailer(unittest.TestCase):
    """Integration targets built from ECS-scoped packages explain why ECS fields were rejected."""

    def _integration_targets(self, scoped: bool) -> list[ValidationTarget]:
        targets = [target for target in _build_plan(_schemas(scoped)) if target.kind == "integration"]
        self.assertTrue(targets, "expected at least one integration validation target")
        return targets

    def test_scoped_package_adds_ecs_scoped_line(self):
        for target in self._integration_targets(scoped=True):
            self.assertEqual(target.integration_types, [PACKAGE])
            # existing lines are preserved
            self.assertIn("Try adding event.module or event.dataset", target.err_trailer)
            self.assertIn(f"Checked against packages [{PACKAGE}]", target.err_trailer)
            self.assertIn("rule: scoping test rule", target.err_trailer)
            # new hint names the scoped package and where to declare populated fields
            self.assertIn(f"ECS-scoped packages [{PACKAGE}]", target.err_trailer)
            self.assertIn("detection_rules/etc/non-ecs-schema.json", target.err_trailer)
            # the schema behind the target really excludes the undeclared ECS field
            self.assertNotIn("process.title", target.schema)
            self.assertIn("destination.ip", target.schema)

    def test_unscoped_package_keeps_trailer_unchanged(self):
        for target in self._integration_targets(scoped=False):
            self.assertIn(f"Checked against packages [{PACKAGE}]", target.err_trailer)
            self.assertNotIn("ECS-scoped", target.err_trailer)
            self.assertNotIn("non-ecs-schema.json", target.err_trailer)
            # full ECS union applies, so the ECS field is accepted
            self.assertIn("process.title", target.schema)

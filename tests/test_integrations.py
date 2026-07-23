# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test integration version resolution against EPR manifest ranges."""

import unittest
import unittest.mock
from types import SimpleNamespace
from typing import ClassVar

from semver import Version

from detection_rules.config import load_current_package_version
from detection_rules.integrations import (
    RELATED_INTEGRATION_GTE_OPERATOR_MIN_STACK,
    IntegrationVersionNotFoundError,
    _find_least_compatible_for_stack,
    _parse_clause,
    _parse_kibana_range,
    _related_integration_version_operator,
    _satisfies_kibana_range,
    collect_schema_fields,
    find_latest_compatible_version,
    find_latest_integration_patch_for_minor,
    get_integration_schema_data,
    get_integration_schema_fields,
    integration_declares_ecs_fields,
    load_integrations_schemas,
    resolve_related_integration_version,
)
from detection_rules.rule_validators import KQLValidator


def _manifest(kibana_version: str) -> dict:
    """Build a minimal manifest dict with the given conditions.kibana.version string."""
    return {"conditions": {"kibana": {"version": kibana_version}}}


class TestParseClause(unittest.TestCase):
    """Test parsing of individual npm-style range clauses."""

    def test_caret(self):
        """Caret range expands to [X.Y.Z, (X+1).0.0)."""
        lo, hi = _parse_clause("^9.1.0")
        self.assertEqual(lo, Version(9, 1, 0))
        self.assertEqual(hi, Version(10, 0, 0))

    def test_tilde(self):
        """Tilde range expands to [X.Y.Z, X.(Y+1).0)."""
        lo, hi = _parse_clause("~8.10.0")
        self.assertEqual(lo, Version(8, 10, 0))
        self.assertEqual(hi, Version(8, 11, 0))

    def test_gte(self):
        """Greater-than-or-equal leaves the upper bound unbounded."""
        lo, hi = _parse_clause(">=8.12.0")
        self.assertEqual(lo, Version(8, 12, 0))
        self.assertIsNone(hi)

    def test_gt(self):
        """Strict greater-than bumps the patch on the lower bound."""
        lo, hi = _parse_clause(">8.12.0")
        self.assertEqual(lo, Version(8, 12, 1))
        self.assertIsNone(hi)

    def test_lte(self):
        """Less-than-or-equal produces an exclusive upper bound at the next patch."""
        lo, hi = _parse_clause("<=9.0.0")
        self.assertEqual(lo, Version(0, 0, 0))
        self.assertEqual(hi, Version(9, 0, 1))

    def test_lt(self):
        """Strict less-than is the exclusive upper bound."""
        lo, hi = _parse_clause("<9.0.0")
        self.assertEqual(lo, Version(0, 0, 0))
        self.assertEqual(hi, Version(9, 0, 0))

    def test_eq_explicit(self):
        """Explicit ``=X.Y.Z`` pins the range to that single version."""
        lo, hi = _parse_clause("=8.12.0")
        self.assertEqual(lo, Version(8, 12, 0))
        self.assertEqual(hi, Version(8, 12, 1))

    def test_bare(self):
        """A bare version token pins the range to that single version."""
        lo, hi = _parse_clause("8.12.0")
        self.assertEqual(lo, Version(8, 12, 0))
        self.assertEqual(hi, Version(8, 12, 1))

    def test_anded_tokens(self):
        """Whitespace-separated tokens in a clause are AND'd together."""
        lo, hi = _parse_clause(">=8.12.0 <9.0.0")
        self.assertEqual(lo, Version(8, 12, 0))
        self.assertEqual(hi, Version(9, 0, 0))

    def test_caret_on_zero_major_raises(self):
        """``^0.x.y`` is unsupported (npm semantics differ) and must raise."""
        with self.assertRaises(ValueError):
            _parse_clause("^0.1.0")

    def test_unsupported_token_raises(self):
        """Unknown operators must raise ``ValueError`` so we fail loudly."""
        with self.assertRaises(ValueError):
            _parse_clause("!9.1.0")


class TestParseKibanaRange(unittest.TestCase):
    """Test parsing of full EPR ``conditions.kibana.version`` strings."""

    def test_single_clause(self):
        """A single clause yields a single [lo, hi) tuple."""
        self.assertEqual(
            _parse_kibana_range("^9.1.0"),
            [(Version(9, 1, 0), Version(10, 0, 0))],
        )

    def test_or_clauses(self):
        """OR'd clauses are parsed independently."""
        self.assertEqual(
            _parse_kibana_range("^8.0.0 || ^9.1.0"),
            [
                (Version(8, 0, 0), Version(9, 0, 0)),
                (Version(9, 1, 0), Version(10, 0, 0)),
            ],
        )


class TestSatisfiesKibanaRange(unittest.TestCase):
    """Test range satisfaction for a given stack version."""

    def test_caret_matches_same_major(self):
        """Caret on X.Y.Z matches later minors/patches within the same major."""
        self.assertTrue(_satisfies_kibana_range(Version(9, 4, 0), "^9.1.0"))
        self.assertTrue(_satisfies_kibana_range(Version(9, 1, 0), "^9.1.0"))

    def test_caret_rejects_lower_minor(self):
        """Caret rejects stacks below its floor minor."""
        self.assertFalse(_satisfies_kibana_range(Version(9, 0, 0), "^9.1.0"))

    def test_caret_rejects_next_major(self):
        """Caret rejects the next major as its upper bound is exclusive."""
        self.assertFalse(_satisfies_kibana_range(Version(10, 0, 0), "^9.1.0"))

    def test_caret_rejects_prior_major(self):
        """Regression: 9.1 must NOT satisfy ^9.4.0 (drove 46 rule failures)."""
        self.assertFalse(_satisfies_kibana_range(Version(9, 1, 0), "^9.4.0"))

    def test_anded_bounds(self):
        """AND'd bounds produce a half-open interval [lo, hi)."""
        self.assertTrue(_satisfies_kibana_range(Version(8, 13, 0), ">=8.12.0 <9.0.0"))
        self.assertFalse(_satisfies_kibana_range(Version(9, 0, 0), ">=8.12.0 <9.0.0"))


class TestFindLatestCompatibleVersion(unittest.TestCase):
    """Regression + behavior coverage for ``find_latest_compatible_version``."""

    def test_picks_latest_compatible_on_same_major(self):
        """Returns the newest manifest whose range admits the stack, with a notice for any skipped newer manifest."""
        manifests = {
            "ded": {
                "1.0.0": _manifest("^8.12.0"),
                "2.0.0": _manifest("^9.0.0"),
                "2.1.0": _manifest("^9.1.0"),
                "3.0.0": _manifest("^9.4.0"),
            }
        }
        version, notice = find_latest_compatible_version("ded", "ded", Version(9, 1, 0), manifests)
        self.assertEqual(version, "2.1.0")
        self.assertTrue(notice)
        self.assertIn("3.0.0", notice[0])
        self.assertIn("9.4.0", notice[1])

    def test_regression_91_does_not_pick_ded_300(self):
        """Regression: on a 9.1 stack we must not select a manifest that requires ^9.4.0."""
        manifests = {
            "ded": {
                "2.1.0": _manifest("^9.1.0"),
                "3.0.0": _manifest("^9.4.0"),
            }
        }
        version, _ = find_latest_compatible_version("ded", "ded", Version(9, 1, 0), manifests)
        self.assertEqual(version, "2.1.0")

    def test_exact_match_on_rule_stack(self):
        """When the only manifest exactly satisfies the stack, notice stays empty."""
        manifests = {"pkg": {"1.0.0": _manifest("^9.4.0")}}
        version, notice = find_latest_compatible_version("pkg", "pkg", Version(9, 4, 0), manifests)
        self.assertEqual(version, "1.0.0")
        self.assertEqual(notice, [""])

    def test_no_compatible_version_raises(self):
        """``ValueError`` when no manifest is compatible with the rule stack."""
        manifests = {"pkg": {"1.0.0": _manifest("^9.4.0")}}
        with self.assertRaises(ValueError):
            find_latest_compatible_version("pkg", "pkg", Version(8, 12, 0), manifests)

    def test_missing_conditions_raises(self):
        """Manifest without ``conditions.kibana.version`` raises ``ValueError``."""
        manifests = {"pkg": {"1.0.0": {"conditions": {}}}}
        with self.assertRaises(ValueError):
            find_latest_compatible_version("pkg", "pkg", Version(9, 1, 0), manifests)

    def test_unknown_package_raises(self):
        """Unknown package raises ``ValueError``."""
        with self.assertRaises(ValueError):
            find_latest_compatible_version("missing", "missing", Version(9, 1, 0), {})

    def test_skips_schema_versions_missing_integration_after_patch_floor(self):
        """A non-zero patch floor can select a package version that contains the requested data stream."""
        package = "pkg"
        integration = "new_ds"
        older_version = "1.0.0"
        newer_version = "1.1.0"
        current_version = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
        required_patch = current_version.patch + 1
        manifests = {
            package: {
                older_version: _manifest(f"^{current_version.major}.0.0"),
                newer_version: _manifest(f"~{current_version.major}.{current_version.minor}.{required_patch}"),
            }
        }
        schemas = {
            older_version: {"old_ds": {}},
            newer_version: {"old_ds": {}, integration: {}},
        }

        with unittest.mock.patch("detection_rules.integrations.load_integrations_manifests", return_value=manifests):
            patch_floor = find_latest_integration_patch_for_minor(
                {package},
                current_version.major,
                current_version.minor,
            )
        self.assertGreater(patch_floor, current_version.patch)

        version, _ = find_latest_compatible_version(
            package,
            integration,
            Version(current_version.major, current_version.minor, patch_floor),
            manifests,
            package_schemas=schemas,
        )
        self.assertEqual(version, newer_version)

        with self.assertRaises(ValueError):
            find_latest_compatible_version(
                package,
                integration,
                current_version,
                manifests,
                package_schemas=schemas,
            )

    def test_required_fields_uses_patch_floor_for_integration_schema(self):
        """Required fields resolve integration schemas using a non-zero patch floor when needed."""
        package = "pkg"
        integration = "new_ds"
        field_name = "pkg.new_ds.some_field"
        current_version = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
        required_patch = current_version.patch + 1
        manifests = {
            package: {
                "1.0.0": _manifest(f"^{current_version.major}.0.0"),
                "1.1.0": _manifest(f"~{current_version.major}.{current_version.minor}.{required_patch}"),
            }
        }
        schemas = {
            package: {
                "1.0.0": {"old_ds": {}},
                "1.1.0": {integration: {field_name: "keyword"}},
            }
        }
        validator = KQLValidator(f"data_stream.dataset:{package}.{integration} and {field_name}:*")

        with (
            unittest.mock.patch("detection_rules.rule.load_integrations_manifests", return_value=manifests),
            unittest.mock.patch("detection_rules.rule.load_integrations_schemas", return_value=schemas),
            unittest.mock.patch("detection_rules.integrations.load_integrations_manifests", return_value=manifests),
        ):
            required_fields = validator.get_required_fields([])

        self.assertIn({"name": field_name, "type": "keyword", "ecs": False}, required_fields)

    def test_non_esql_validation_uses_patch_floor_for_integration_schema(self):
        """Non-ES|QL schema validation resolves integration schemas using the inferred patch floor."""
        package = "pkg"
        integration = "new_ds"
        field_name = "pkg.new_ds.some_field"
        manifests = {
            package: {
                "1.0.0": _manifest("^9.0.0"),
                "1.1.0": _manifest("~9.2.4"),
            }
        }
        schemas = {
            package: {
                "1.0.0": {"old_ds": {}},
                "1.1.0": {integration: {field_name: "keyword"}},
            }
        }
        data = SimpleNamespace(language="kuery", get=lambda key, default=None: False if key == "notify" else default)
        meta = SimpleNamespace(
            maturity="production",
            get_validation_stack_versions=lambda: {"9.2.0": {"ecs": "test-ecs", "endgame": "test-endgame"}},
        )

        with (
            unittest.mock.patch("detection_rules.integrations.load_integrations_manifests", return_value=manifests),
            unittest.mock.patch("detection_rules.integrations.load_integrations_schemas", return_value=schemas),
            unittest.mock.patch("detection_rules.integrations.ecs.get_schema", return_value={}),
            unittest.mock.patch("detection_rules.integrations.ecs.flatten_multi_fields", return_value={}),
        ):
            schema_data = list(
                get_integration_schema_data(
                    data,
                    meta,
                    [{"package": package, "integration": integration}],
                )
            )

        self.assertEqual(len(schema_data), 1)
        self.assertEqual(schema_data[0]["package_version"], "1.1.0")
        self.assertEqual(schema_data[0]["stack_version"], "9.2.0")


class TestResolveRelatedIntegrationVersion(unittest.TestCase):
    """Behavior coverage for ``resolve_related_integration_version``."""

    def test_uses_current_stack_single_manifest_version(self):
        """Returns only the least compatible manifest version for the current package stack."""
        manifests = {
            "pkg": {
                "1.0.0": _manifest("^8.0.0"),
                "1.5.0": _manifest("^8.0.0"),
                "2.0.0": _manifest("^9.0.0"),
                "2.5.0": _manifest("^9.1.0"),
                "3.0.0": _manifest("^10.0.0"),
            }
        }

        with unittest.mock.patch("detection_rules.integrations.load_current_package_version", return_value="8.19.0"):
            stack_8 = resolve_related_integration_version("pkg", manifests)
        with unittest.mock.patch("detection_rules.integrations.load_current_package_version", return_value="9.1.0"):
            stack_9 = resolve_related_integration_version("pkg", manifests)
        with unittest.mock.patch("detection_rules.integrations.load_current_package_version", return_value="9.5.0"):
            stack_95 = resolve_related_integration_version("pkg", manifests)
        with unittest.mock.patch("detection_rules.integrations.load_current_package_version", return_value="9.6.0"):
            stack_96 = resolve_related_integration_version("pkg", manifests)
        with unittest.mock.patch("detection_rules.integrations.load_current_package_version", return_value="10.0.0"):
            stack_10 = resolve_related_integration_version("pkg", manifests)

        self.assertEqual(stack_8.expression, "^1.0.0")
        self.assertEqual(stack_8.manifest_versions, ("1.0.0",))
        self.assertEqual(stack_9.expression, "^2.0.0")
        self.assertEqual(stack_9.manifest_versions, ("2.0.0",))
        # ≥ 9.5 defaults to >= without an env gate.
        self.assertEqual(stack_95.expression, ">=2.0.0")
        self.assertEqual(stack_95.manifest_versions, ("2.0.0",))
        self.assertEqual(stack_96.expression, ">=2.0.0")
        self.assertEqual(stack_96.manifest_versions, ("2.0.0",))
        self.assertEqual(stack_10.expression, ">=3.0.0")
        self.assertEqual(stack_10.manifest_versions, ("3.0.0",))

    def test_emit_transform_rewrites_caret_on_min_stack(self):
        """Emit transform rewrites remaining caret related_integrations on ≥ 9.5."""
        from detection_rules.stack_emit import apply_emit_transforms

        self.assertEqual(_related_integration_version_operator(Version(9, 4, 0)), "^")
        self.assertEqual(_related_integration_version_operator(RELATED_INTEGRATION_GTE_OPERATOR_MIN_STACK), ">=")

        obj_94 = {"related_integrations": [{"package": "pkg", "version": "^2.0.0"}]}
        obj_95 = {"related_integrations": [{"package": "pkg", "version": "^2.0.0"}]}
        obj_10 = {"related_integrations": [{"package": "pkg", "version": "^3.0.0"}]}
        apply_emit_transforms(obj_94, stack="9.4.0")
        apply_emit_transforms(obj_95, stack="9.5.0")
        apply_emit_transforms(obj_10, stack="10.0.0")

        self.assertEqual(obj_94["related_integrations"][0]["version"], "^2.0.0")
        self.assertEqual(obj_95["related_integrations"][0]["version"], ">=2.0.0")
        self.assertEqual(obj_10["related_integrations"][0]["version"], ">=3.0.0")

    def test_keeps_zero_major_when_only_stable_option_missing(self):
        """Keep 0.x manifest versions when no major >= 1 option exists."""
        manifests = {"pkg": {"0.5.0": _manifest("^8.0.0")}}
        with unittest.mock.patch("detection_rules.integrations.load_current_package_version", return_value="8.19.0"):
            result = resolve_related_integration_version("pkg", manifests)
        self.assertEqual(result.manifest_versions, ("0.5.0",))

    def test_raises_when_current_stack_is_incompatible(self):
        """Raises when the current package stack cannot use any manifest version."""
        manifests = {"pkg": {"1.0.0": _manifest("^9.4.0")}}
        with (
            unittest.mock.patch("detection_rules.integrations.load_current_package_version", return_value="8.19.0"),
            self.assertRaises(IntegrationVersionNotFoundError),
        ):
            resolve_related_integration_version("pkg", manifests)


class TestResolveRelatedIntegrationVersionSchemaAware(unittest.TestCase):
    """Schema-aware data stream filtering for related integration version resolution."""

    def test_skips_versions_missing_integration(self):
        """Kibana-compatible versions whose schema lacks the integration are skipped for a later one."""
        manifests = {
            "pkg": {
                "1.0.0": _manifest("^8.12.0"),
                "1.5.0": _manifest("^8.12.0"),
                "1.9.0": _manifest("^8.12.0"),
            }
        }
        schemas = {
            "pkg": {
                "1.0.0": {"existing_ds": {}},
                "1.5.0": {"existing_ds": {}},
                "1.9.0": {"existing_ds": {}, "new_ds": {}},
            }
        }
        with (
            unittest.mock.patch("detection_rules.integrations.load_current_package_version", return_value="8.12.0"),
            unittest.mock.patch("detection_rules.integrations.load_integrations_schemas", return_value=schemas),
        ):
            new_ds = resolve_related_integration_version("pkg", manifests, integration="new_ds")
            self.assertIn("1.9.0", new_ds.manifest_versions)
            self.assertNotIn("1.0.0", new_ds.manifest_versions)
            self.assertNotIn("1.5.0", new_ds.manifest_versions)

            existing_ds = resolve_related_integration_version("pkg", manifests, integration="existing_ds")
            self.assertEqual(existing_ds.manifest_versions, ("1.0.0",))

    def test_no_schema_data_falls_back_to_kibana_only(self):
        """Versions without schema data are not filtered; kibana compatibility alone decides."""
        manifests = {"pkg": {"1.0.0": _manifest("^8.12.0"), "1.5.0": _manifest("^8.12.0")}}
        with (
            unittest.mock.patch("detection_rules.integrations.load_current_package_version", return_value="8.12.0"),
            unittest.mock.patch("detection_rules.integrations.load_integrations_schemas", return_value={}),
        ):
            result = resolve_related_integration_version("pkg", manifests, integration="new_ds")
            self.assertEqual(result.manifest_versions, ("1.0.0",))

    def test_all_compatible_versions_missing_integration_raises(self):
        """Raise when every kibana-compatible version's schema lacks the requested integration."""
        manifests = {"pkg": {"1.0.0": _manifest("^8.12.0"), "1.5.0": _manifest("^8.12.0")}}
        schemas = {"pkg": {"1.0.0": {"existing_ds": {}}, "1.5.0": {"existing_ds": {}}}}
        with (
            unittest.mock.patch("detection_rules.integrations.load_current_package_version", return_value="8.12.0"),
            unittest.mock.patch("detection_rules.integrations.load_integrations_schemas", return_value=schemas),
            self.assertRaises(IntegrationVersionNotFoundError),
        ):
            resolve_related_integration_version("pkg", manifests, integration="new_ds")

    def test_schema_filter_excludes_legacy_zero_major(self):
        """Schema filtering must not retain older versions without the requested integration."""
        manifests = {
            "pkg": {
                "0.0.2": _manifest("^7.9.0"),
                "1.0.0": _manifest("^8.0.0"),
                "1.37.0": _manifest("^9.0.0"),
            }
        }
        schemas = {
            "pkg": {
                "0.0.2": {"other_ds": {}},
                "1.0.0": {"other_ds": {}},
                "1.37.0": {"aadgraphactivitylogs": {}},
            }
        }
        with (
            unittest.mock.patch("detection_rules.integrations.load_current_package_version", return_value="9.0.0"),
            unittest.mock.patch("detection_rules.integrations.load_integrations_schemas", return_value=schemas),
        ):
            result = resolve_related_integration_version("pkg", manifests, integration="aadgraphactivitylogs")
            self.assertEqual(result.manifest_versions, ("1.37.0",))
            self.assertEqual(result.expression, "^1.37.0")

    def test_azure_aadgraphactivitylogs_schema_filter(self):
        """aadgraphactivitylogs resolution matches current-stack compatibility plus bundled schemas."""
        from detection_rules.integrations import load_integrations_manifests, load_integrations_schemas

        schemas = load_integrations_schemas()
        manifests = load_integrations_manifests()
        current_version = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
        expected = _find_least_compatible_for_stack(
            current_version,
            manifests["azure"],
            "aadgraphactivitylogs",
            schemas["azure"],
        )
        if expected is None:
            with self.assertRaises(IntegrationVersionNotFoundError):
                resolve_related_integration_version("azure", manifests, integration="aadgraphactivitylogs")
            return

        operator = _related_integration_version_operator(current_version)
        result = resolve_related_integration_version("azure", manifests, integration="aadgraphactivitylogs")
        self.assertEqual(result.manifest_versions, (expected,))
        self.assertEqual(result.expression, f"{operator}{expected}")
        floor_versions = [
            version
            for version in sorted(schemas["azure"], key=Version.parse)
            if "aadgraphactivitylogs" in schemas["azure"][version]
        ]
        self.assertEqual(floor_versions[0], "1.37.0")


class TestMetadataPackageRowDedupe(unittest.TestCase):
    """Skip redundant metadata package rows when query datasets already cover the package."""

    def test_metadata_package_row_needed_helper(self):
        from detection_rules.rule import _metadata_package_row_needed

        self.assertFalse(_metadata_package_row_needed("azure", {"azure.signinlogs"}))
        self.assertFalse(_metadata_package_row_needed("aws", {"aws.cloudtrail", "aws.billing"}))
        self.assertFalse(_metadata_package_row_needed("endpoint", {"endpoint.events.api"}))
        self.assertFalse(_metadata_package_row_needed("windows", {"windows.sysmon_operational"}))
        self.assertTrue(_metadata_package_row_needed("azure", set()))
        self.assertTrue(_metadata_package_row_needed("aws_bedrock", set()))
        self.assertTrue(_metadata_package_row_needed("endpoint", set()))

    def test_non_dataset_package_skips_metadata_row_when_query_has_datasets(self):
        from pathlib import Path

        from detection_rules.integrations import load_integrations_manifests
        from detection_rules.rule import TOMLRuleContents
        from detection_rules.rule_loader import RuleCollection

        manifests = load_integrations_manifests()
        rule = RuleCollection().load_file(Path("rules/windows/persistence_sysmon_wmi_event_subscription.toml"))
        packaged = TOMLRuleContents.get_packaged_integrations(rule.contents.data, rule.contents.metadata, manifests)
        packages = [entry["package"] for entry in packaged]
        self.assertEqual(packages.count("endpoint"), 1)
        self.assertEqual(packages.count("windows"), 1)

        api = rule.contents.to_api_format()
        endpoint_rows = [row for row in api["related_integrations"] if row["package"] == "endpoint"]
        windows_rows = [row for row in api["related_integrations"] if row["package"] == "windows"]
        self.assertEqual(len(endpoint_rows), 1)
        self.assertEqual(len(windows_rows), 1)
        self.assertRegex(endpoint_rows[0]["version"], r"^(?:\^|>=)")
        self.assertRegex(windows_rows[0]["version"], r"^(?:\^|>=)")
        self.assertNotIn(" || ", endpoint_rows[0]["version"])
        self.assertNotIn(" || ", windows_rows[0]["version"])

    def test_unsupported_generated_related_integration_row_is_skipped(self):
        """Generated rows for data streams unavailable on the package stack should not block API conversion."""
        from pathlib import Path

        from detection_rules.rule_loader import RuleCollection

        class RelatedIntegrationVersionStub:
            expression = ">=1.0.0"
            manifest_versions = ("1.0.0",)

        def compatible_side_effect(package, packages_manifest, integration=None):
            if package == "unsupported":
                raise IntegrationVersionNotFoundError(f"no compatible version for integration {package}:{integration}")
            return RelatedIntegrationVersionStub()

        packages_manifest = {"endpoint": {"1.0.0": {"policy_templates": ["endpoint"]}}}
        packaged_integrations = [
            {"package": "endpoint", "integration": "endpoint"},
            {"package": "unsupported", "integration": "new_ds"},
        ]
        rule = RuleCollection().load_file(Path("rules/windows/persistence_sysmon_wmi_event_subscription.toml"))

        with (
            unittest.mock.patch("detection_rules.rule.load_integrations_manifests", return_value=packages_manifest),
            unittest.mock.patch(
                "detection_rules.rule.TOMLRuleContents.get_packaged_integrations",
                return_value=packaged_integrations,
            ),
            unittest.mock.patch(
                "detection_rules.rule.resolve_related_integration_version",
                side_effect=compatible_side_effect,
            ),
            unittest.mock.patch("detection_rules.rule.QueryRuleData.get_required_fields", return_value=[]),
        ):
            related_integrations = rule.contents.to_api_format()["related_integrations"]

        self.assertEqual(
            related_integrations, [{"package": "endpoint", "integration": "endpoint", "version": ">=1.0.0"}]
        )


class TestEsqlPackagedIntegrations(unittest.TestCase):
    """ES|QL must not emit a redundant metadata package row when datasets cover the package."""

    def test_metadata_package_row_needed_helper(self):
        from detection_rules.rule import _esql_metadata_package_row_needed

        self.assertFalse(_esql_metadata_package_row_needed("azure", {"azure.signinlogs"}))
        self.assertFalse(_esql_metadata_package_row_needed("aws", {"aws.cloudtrail", "aws.billing"}))
        self.assertTrue(_esql_metadata_package_row_needed("azure", set()))
        self.assertTrue(_esql_metadata_package_row_needed("aws_bedrock", set()))


class TestIntegrationScopedEcsValidation(unittest.TestCase):
    """ECS fields must be scoped to what the rule's integrations declare (ecs.yml)."""

    ECS_SCHEMA: ClassVar[dict[str, str]] = {
        "process.title": "keyword",
        "destination.ip": "ip",
        "process.name": "keyword",
    }

    @staticmethod
    def _strict_schemas(package: str, integration: str) -> dict:
        """Package version that explicitly declares its ECS fields."""
        return {
            package: {
                "1.0.0": {
                    "_uses_ecs_mappings": False,
                    integration: {
                        "data_stream.dataset": "constant_keyword",
                        "destination.ip": "ip",
                        f"{package}.custom_field": "keyword",
                        "_ecs_declared": ["destination.ip"],
                    },
                }
            }
        }

    @staticmethod
    def _ecs_mappings_schemas(package: str, integration: str) -> dict:
        """Package version that declares no ECS fields and inherits them via ecs@mappings."""
        return {
            package: {
                "1.0.0": {
                    "_uses_ecs_mappings": True,
                    integration: {
                        "data_stream.dataset": "constant_keyword",
                        f"{package}.custom_field": "keyword",
                    },
                }
            }
        }

    def _get_schema(self, schemas: dict, package: str, integration: str) -> dict:
        manifests = {package: {"1.0.0": _manifest("^9.0.0")}}
        data = SimpleNamespace(get=lambda key, default=None: False if key == "notify" else default)
        with unittest.mock.patch(
            "detection_rules.integrations.find_latest_integration_patch_for_minor", return_value=0
        ):
            schema, _ = get_integration_schema_fields(
                schemas,
                package,
                integration,
                Version.parse("9.0.0"),
                manifests,
                self.ECS_SCHEMA,
                data,
            )
        return schema

    def test_strict_integration_rejects_undeclared_ecs_field(self):
        """An ECS field the integration does not declare must not enter the schema."""
        schema = self._get_schema(self._strict_schemas("network_traffic", "icmp"), "network_traffic", "icmp")

        self.assertNotIn("process.title", schema)
        self.assertIn("destination.ip", schema)
        self.assertIn("network_traffic.custom_field", schema)
        self.assertNotIn("_ecs_declared", schema)

    def test_ecs_mappings_integration_passes_all_ecs_fields(self):
        """Packages relying on ecs@mappings keep the full ECS schema."""
        schema = self._get_schema(self._ecs_mappings_schemas("cloud_defend", "process"), "cloud_defend", "process")

        self.assertIn("process.title", schema)
        self.assertIn("process.name", schema)
        self.assertIn("cloud_defend.custom_field", schema)

    def test_legacy_cache_format_keeps_full_ecs(self):
        """Cached schemas without ECS scoping metadata preserve the historical behavior."""
        schemas = self._strict_schemas("pkg", "ds")
        del schemas["pkg"]["1.0.0"]["_uses_ecs_mappings"]
        del schemas["pkg"]["1.0.0"]["ds"]["_ecs_declared"]
        schema = self._get_schema(schemas, "pkg", "ds")

        self.assertIn("process.title", schema)

    def test_ecs_additions_override_extends_strict_schema(self):
        """Pipeline-injected fields listed in integration-ecs-additions.json pass validation."""
        additions = {"network_traffic": {"icmp": ["process.title"], "_all": ["process.name"]}}
        with unittest.mock.patch("detection_rules.integrations.load_integration_ecs_additions", return_value=additions):
            schema = self._get_schema(self._strict_schemas("network_traffic", "icmp"), "network_traffic", "icmp")

        self.assertIn("process.title", schema)
        self.assertIn("process.name", schema)

    def test_integration_declares_ecs_fields_package_wide(self):
        """Package-wide resolution is strict only when every data stream declares ECS fields."""
        schemas = {
            "pkg": {
                "1.0.0": {
                    "_uses_ecs_mappings": False,
                    "declared": {"destination.ip": "ip", "_ecs_declared": ["destination.ip"]},
                    "undeclared": {"pkg.custom": "keyword"},
                }
            }
        }
        self.assertTrue(integration_declares_ecs_fields(schemas["pkg"] and schemas, "pkg", "1.0.0", "declared"))
        self.assertFalse(integration_declares_ecs_fields(schemas, "pkg", "1.0.0", "undeclared"))
        self.assertFalse(integration_declares_ecs_fields(schemas, "pkg", "1.0.0", None))

        schemas["pkg"]["1.0.0"]["undeclared"]["_ecs_declared"] = ["process.name"]
        self.assertTrue(integration_declares_ecs_fields(schemas, "pkg", "1.0.0", None))

    def test_collect_schema_fields_filters_metadata(self):
        """Metadata keys must not leak into the collected field schemas."""
        schemas = self._strict_schemas("pkg", "ds")

        integration_fields = collect_schema_fields(schemas, "pkg", "1.0.0", "ds")
        self.assertNotIn("_ecs_declared", integration_fields)

        package_fields = collect_schema_fields(schemas, "pkg", "1.0.0")
        self.assertNotIn("_ecs_declared", package_fields)
        self.assertNotIn("_uses_ecs_mappings", package_fields)
        self.assertIn("destination.ip", package_fields)

    def test_required_fields_mark_undeclared_ecs_fields(self):
        """required_fields entries flip to ecs=False when the integration lacks the field."""
        package = "pkg"
        integration = "ds"
        manifests = {package: {"1.0.0": _manifest("^9.0.0")}}
        schemas = self._strict_schemas(package, integration)
        validator = KQLValidator(
            f"data_stream.dataset:{package}.{integration} and destination.ip:* and process.title:foo"
        )

        with (
            unittest.mock.patch("detection_rules.rule.load_integrations_manifests", return_value=manifests),
            unittest.mock.patch("detection_rules.rule.load_integrations_schemas", return_value=schemas),
            unittest.mock.patch("detection_rules.integrations.load_integrations_manifests", return_value=manifests),
            unittest.mock.patch("detection_rules.rule.find_latest_integration_patch_for_minor", return_value=0),
            unittest.mock.patch("detection_rules.integrations.find_latest_integration_patch_for_minor", return_value=0),
        ):
            required_fields = validator.get_required_fields([])

        by_name = {f["name"]: f for f in required_fields}
        self.assertTrue(by_name["destination.ip"]["ecs"])
        self.assertFalse(by_name["process.title"]["ecs"])
        self.assertEqual(by_name["process.title"]["type"], "unknown")


class TestIntegrationScopedEcsCachedSchema(unittest.TestCase):
    """The committed schema cache must carry ECS scoping metadata for known archetypes."""

    @classmethod
    def setUpClass(cls):
        cls.schemas = load_integrations_schemas()

    def test_network_traffic_icmp_is_strict(self):
        """network_traffic declares its ECS fields; process.title is not one of them."""
        version = "1.33.0"
        self.assertTrue(integration_declares_ecs_fields(self.schemas, "network_traffic", version, "icmp"))
        fields = collect_schema_fields(self.schemas, "network_traffic", version, "icmp")
        self.assertIn("destination.ip", fields)
        self.assertNotIn("process.title", fields)

    def test_cloud_defend_uses_ecs_mappings(self):
        """cloud_defend declares no ECS fields and must keep the full ECS fallback."""
        for version_schema in self.schemas["cloud_defend"].values():
            self.assertTrue(version_schema["_uses_ecs_mappings"])
        version = sorted(self.schemas["cloud_defend"], key=Version.parse)[-1]
        self.assertFalse(integration_declares_ecs_fields(self.schemas, "cloud_defend", version, "process"))

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test integration version resolution against EPR manifest ranges."""

import io
import unittest
import unittest.mock
import zipfile
from types import SimpleNamespace

import yaml
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
    elastic_agent_fields,
    find_latest_compatible_version,
    find_latest_integration_patch_for_minor,
    get_integration_schema_data,
    get_integration_schema_fields,
    load_integrations_schemas,
    parse_version_schema,
    resolve_related_integration_version,
)
from detection_rules.rule_validators import KQLValidator
from detection_rules.utils import clear_caches

PACKAGE_STACK_VERSION = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
# On 8.x stacks Azure rules resolve to azure ^1.0.0, whose lowest version predates the events policy template (1.20.0),
# and the Azure releases with aadgraphactivitylogs (1.37.0+) need a later 8.19 patch, so no events row is listed there
skip_before_9x_azure_routing = unittest.skipIf(
    PACKAGE_STACK_VERSION < Version.parse("9.0.0"),
    "Azure events policy template rows are only resolved on 9.x stacks",
)


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

    def setUp(self):
        # The integration schema helpers memoize on (package, integration, stack version) and load
        # the bundled manifests/schemas internally, so results resolved against a patched loader
        # must not leak into other tests (or the real data) through the cache.
        clear_caches()
        self.addCleanup(clear_caches)

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
            unittest.mock.patch("detection_rules.integrations.load_integrations_manifests", return_value=manifests),
            unittest.mock.patch("detection_rules.integrations.load_integrations_schemas", return_value=schemas),
        ):
            required_fields = validator.get_required_fields([])

        self.assertIn({"name": field_name, "type": "keyword", "ecs": False}, required_fields)

    def test_required_fields_resolve_ecs_from_other_stack_pins(self):
        """A field missing from this stack's ECS pin but present in another pin's ECS resolves as ECS.

        Keeps `ecs`/`type` identical on every release branch so the version lock hash does not
        oscillate between branches (e.g. gen_ai.* on 8.19, which is pinned to ECS 8.17.0).
        """
        from detection_rules.schemas import get_stack_schemas as real_get_stack_schemas

        field_name = "gen_ai.tool.name"  # added to ECS in 9.1.0
        current_version = str(Version.parse(load_current_package_version(), optional_minor_and_patch=True))
        pinned = dict(real_get_stack_schemas()[current_version], ecs="8.17.0")

        def required(stack_map: dict) -> dict:
            validator = KQLValidator(f"{field_name}:*")
            with (
                unittest.mock.patch("detection_rules.rule.get_stack_schemas", return_value={current_version: pinned}),
                unittest.mock.patch("detection_rules.rule.load_stack_schema_map", return_value=stack_map),
            ):
                return {f["name"]: f for f in validator.get_required_fields([])}

        only_old_pin = required({"8.19.0": {"ecs": "8.17.0"}})
        self.assertEqual(only_old_pin[field_name], {"name": field_name, "type": "unknown", "ecs": False})

        with_newer_pin = required({"8.19.0": {"ecs": "8.17.0"}, "9.4.0": {"ecs": "9.4.0"}})
        self.assertEqual(with_newer_pin[field_name], {"name": field_name, "type": "keyword", "ecs": True})

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


class TestRelatedIntegrationPolicyTemplates(unittest.TestCase):
    """related_integrations.integration names the policy template that collects the queried data stream."""

    def test_manifest_schema_keeps_policy_template_data_streams(self):
        from marshmallow import EXCLUDE

        from detection_rules.integrations import IntegrationManifestSchema

        raw = {
            "name": "azure",
            "version": "1.0.0",
            "release": "ga",
            "description": "",
            "download": "",
            "conditions": {"kibana": {"version": "^8.0.0"}},
            "policy_templates": [
                {"name": "adlogs", "title": "Microsoft Entra ID", "data_streams": ["auditlogs", "signinlogs"]},
                {"name": "activitylogs", "data_streams": ["activitylogs"]},
                {"name": "no_streams"},
            ],
        }
        loaded = IntegrationManifestSchema(unknown=EXCLUDE).load(raw)
        self.assertEqual(loaded["policy_templates"], ["adlogs", "activitylogs", "no_streams"])
        self.assertEqual(
            loaded["policy_template_data_streams"],
            {"adlogs": ["auditlogs", "signinlogs"], "activitylogs": ["activitylogs"]},
        )

    def test_get_policy_template_for_data_stream(self):
        from detection_rules.integrations import get_policy_template_for_data_stream

        manifest = {
            "policy_templates": ["adlogs", "activitylogs"],
            "policy_template_data_streams": {"adlogs": ["auditlogs", "signinlogs"], "activitylogs": ["activitylogs"]},
        }
        self.assertEqual(get_policy_template_for_data_stream(manifest, "activitylogs"), "activitylogs")
        self.assertEqual(get_policy_template_for_data_stream(manifest, "signinlogs"), "adlogs")
        self.assertIsNone(get_policy_template_for_data_stream(manifest, "unknown"))
        # manifests built before data streams were kept only resolve policy template names
        self.assertIsNone(get_policy_template_for_data_stream({"policy_templates": ["adlogs"]}, "signinlogs"))

    def test_parse_version_routing_rules(self):
        from detection_rules.integrations import parse_version_routing_rules

        routing_rules = [
            {
                "source_dataset": "azure.events",
                "rules": [
                    {"target_dataset": "azure.signinlogs", "if": "ctx.event?.dataset == 'azure.signinlogs'"},
                    {"target_dataset": "azure.activitylogs", "if": "ctx.event?.dataset == 'azure.activitylogs'"},
                    # a templated target is resolved per document, another package has its own policy templates
                    {"target_dataset": "{{event.dataset}}", "if": "true"},
                    {"target_dataset": "aws.cloudtrail", "if": "true"},
                    {"target_dataset": ["azure.auditlogs", "azure.events"], "if": "true"},
                ],
            }
        ]
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zip_ref:
            zip_ref.writestr("azure-1.0.0/data_stream/events/routing_rules.yml", yaml.safe_dump(routing_rules))
            zip_ref.writestr("azure-1.0.0/data_stream/activitylogs/fields/fields.yml", "[]")
        with zipfile.ZipFile(buffer) as zip_ref:
            self.assertEqual(
                parse_version_routing_rules(zip_ref, "azure"),
                {"events": ["activitylogs", "auditlogs", "signinlogs"]},
            )

    def test_routing_rule_sources_and_targets_have_a_policy_template(self):
        from detection_rules.integrations import (
            get_policy_template_for_data_stream,
            load_integrations_manifests,
            load_integrations_routing_rules,
        )

        manifests = load_integrations_manifests()
        routing_rules = load_integrations_routing_rules()
        # azure.events reroutes every Azure log category; the rule build depends on this data
        self.assertIn("azure", routing_rules)
        for package, versions in routing_rules.items():
            # An incremental build-schemas run records an empty map for a package whose versions it did not parse
            common_versions = versions.keys() & manifests.get(package, {}).keys()
            if not common_versions:
                continue
            latest = max(common_versions, key=Version.parse)
            manifest = manifests[package][latest]
            # the rule build only lists a rerouting policy template for a package with more than one
            if len(manifest.get("policy_templates", [])) < 2:
                continue
            for source, targets in versions[latest].items():
                with self.subTest(package=package, source=source):
                    self.assertIsNotNone(get_policy_template_for_data_stream(manifest, source))
                for target in targets:
                    with self.subTest(package=package, target=target):
                        self.assertIsNotNone(get_policy_template_for_data_stream(manifest, target))

    def test_rerouting_policy_templates_from_routing_rules(self):
        from detection_rules.rule import TOMLRuleContents

        manifests = {
            "pkg": {"1.0.0": {"policy_templates": ["router", "a"]}},
            "single": {"1.0.0": {"policy_templates": ["entity"]}},
        }
        routing_rules = {"pkg": {"1.0.0": {"router": ["a"]}}, "single": {"1.0.0": {"entity": ["device"]}}}
        with unittest.mock.patch("detection_rules.rule.load_integrations_routing_rules", return_value=routing_rules):
            get_templates = TOMLRuleContents._get_rerouting_policy_templates  # noqa: SLF001
            self.assertEqual(get_templates("pkg", "a", ["1.0.0"], manifests), ["router"])
            self.assertEqual(get_templates("pkg", "b", ["1.0.0"], manifests), [])
            self.assertEqual(get_templates("pkg", None, ["1.0.0"], manifests), [])
            # a version without routing rules does not reroute
            self.assertEqual(get_templates("pkg", "a", ["2.0.0"], manifests), [])
            # Kibana matches the package row of a package with one policy template
            self.assertEqual(get_templates("single", "device", ["1.0.0"], manifests), [])

    def _azure_rows(self, path: str) -> list[dict]:
        from pathlib import Path

        from detection_rules.rule_loader import RuleCollection

        rule = RuleCollection().load_file(Path(path))
        rows = rule.contents.to_api_format()["related_integrations"]
        return sorted((row for row in rows if row["package"] == "azure"), key=lambda row: row.get("integration", ""))

    @skip_before_9x_azure_routing
    def test_entra_id_data_stream_maps_to_adlogs_and_events(self):
        rows = self._azure_rows("rules/cross-platform/initial_access_azure_o365_with_network_alert.toml")
        self.assertEqual([row.get("integration") for row in rows], ["adlogs", "events"])
        self.assertEqual(len({row["version"] for row in rows}), 1)

    @skip_before_9x_azure_routing
    def test_activitylogs_adds_events(self):
        rows = self._azure_rows("rules/integrations/azure/credential_access_azure_storage_account_keys_accessed.toml")
        self.assertEqual([row.get("integration") for row in rows], ["activitylogs", "events"])
        self.assertEqual(rows[0]["version"], rows[1]["version"])

    @skip_before_9x_azure_routing
    def test_events_takes_highest_version_of_rerouted_data_streams(self):
        rows = self._azure_rows("rules/integrations/azure/credential_access_device_code_signin_aad_graph_enum.toml")
        by_template = {row.get("integration"): row["version"] for row in rows}
        self.assertEqual(set(by_template), {"aadgraphactivitylogs", "adlogs", "events"})
        self.assertEqual(by_template["events"], by_template["aadgraphactivitylogs"])


class TestEsqlPackagedIntegrations(unittest.TestCase):
    """ES|QL must not emit a redundant metadata package row when datasets cover the package."""

    def test_metadata_package_row_needed_helper(self):
        from detection_rules.rule import _esql_metadata_package_row_needed

        self.assertFalse(_esql_metadata_package_row_needed("azure", {"azure.signinlogs"}))
        self.assertFalse(_esql_metadata_package_row_needed("aws", {"aws.cloudtrail", "aws.billing"}))
        self.assertTrue(_esql_metadata_package_row_needed("azure", set()))
        self.assertTrue(_esql_metadata_package_row_needed("aws_bedrock", set()))

    def test_index_datasets_from_from_sources(self):
        from detection_rules.esql import get_esql_query_index_datasets

        schemas = {
            "azure": {"1.0.0": {"activitylogs": {}, "signinlogs": {}}},
            "endpoint": {"9.0.0": {"process": {}, "network": {}}},
            "aws": {"8.0.0": {"cloudtrail": {}, "cloudtrail_otel": {}}, "8.9.0": {"eks_audit": {}}},
            "apache_tomcat": {"1.0.0": {"catalina": {}}},
            "system": {"1.0.0": {"security": {}, "auth": {}}},
        }
        query = (
            "FROM logs-azure.activitylogs-*, logs-endpoint.events.process-*, remote:logs-aws.eks_audit-*, "
            # several data streams, or none, match these patterns, so they name no single data stream
            "logs-azure.*, logs-aws.cloudtrail*, logs-apache_tomcat.error-*, logs-*, metrics-* "
            "METADATA _id, _version, _index | KEEP _id"
        )
        self.assertEqual(
            [str(dataset) for dataset in get_esql_query_index_datasets(query, schemas)],
            ["azure.activitylogs", "endpoint.process", "aws.eks_audit"],
        )

    def test_index_datasets_match_up_to_the_namespace_boundary(self):
        from detection_rules.esql import get_esql_query_index_datasets

        query = "FROM logs-aws.cloudtrail_otel-* METADATA _id, _version, _index | KEEP _id"
        # an exact source names its own data stream, not a data stream whose name is a prefix of it
        both = {"aws": {"8.0.0": {"cloudtrail": {}, "cloudtrail_otel": {}}}}
        self.assertEqual(
            [str(dataset) for dataset in get_esql_query_index_datasets(query, both)], ["aws.cloudtrail_otel"]
        )
        prefix_only = {"aws": {"8.0.0": {"cloudtrail": {}}}}
        self.assertEqual(get_esql_query_index_datasets(query, prefix_only), [])

    def _related_integrations(self, path: str) -> list[dict]:
        from pathlib import Path

        from detection_rules.rule_loader import RuleCollection

        rule = RuleCollection().load_file(Path(path))
        rows = rule.contents.to_api_format()["related_integrations"]
        return sorted(rows, key=lambda row: (row["package"], row.get("integration", "")))

    @skip_before_9x_azure_routing
    def test_from_data_stream_resolves_policy_template(self):
        # the query compares no dataset; FROM logs-azure.activitylogs-* names the data stream
        rows = self._related_integrations(
            "rules/cross-platform/execution_azure_vm_run_command_powershell_unrestricted_script.toml"
        )
        self.assertEqual(
            [(row["package"], row.get("integration")) for row in rows],
            [("azure", "activitylogs"), ("azure", "events"), ("endpoint", None)],
        )

    def test_from_unknown_data_stream_keeps_package_row(self):
        rows = self._related_integrations(
            "rules/cross-platform/reconnaissance_web_server_unusual_spike_in_error_logs.toml"
        )
        self.assertIn("apache_tomcat", [row["package"] for row in rows])

    def test_compared_dataset_skips_from_data_streams_of_the_same_package(self):
        # FROM data streams are only added for packages whose datasets the query does not compare. Merging them per
        # data stream would also widen the ES|QL validation schema, so a compared dataset wins for the whole package.
        import dataclasses
        from pathlib import Path

        from detection_rules.integrations import load_integrations_manifests
        from detection_rules.rule import TOMLRuleContents
        from detection_rules.rule_loader import RuleCollection

        rule = RuleCollection().load_file(
            Path("rules/cross-platform/execution_azure_vm_run_command_powershell_unrestricted_script.toml")
        )
        data = dataclasses.replace(
            rule.contents.data,
            query=(
                "FROM logs-azure.activitylogs-*, logs-azure.signinlogs-* METADATA _id, _version, _index "
                '| WHERE event.dataset == "azure.signinlogs" | KEEP _id'
            ),
        )
        rows = TOMLRuleContents.get_packaged_integrations(data, rule.contents.metadata, load_integrations_manifests())
        azure_integrations = {row["integration"] for row in rows or [] if row["package"] == "azure"}
        self.assertEqual(azure_integrations, {"signinlogs"})


class TestIntegrationSchemaWithoutEcsUnion(unittest.TestCase):
    """Integration validation checks a query against the package field schema only, never the full ECS schema."""

    def setUp(self):
        # the schema helpers memoize and load the bundled manifests/schemas internally; see
        # TestFindLatestCompatibleVersion.setUp
        clear_caches()
        self.addCleanup(clear_caches)

    def test_undeclared_ecs_field_is_not_in_schema(self):
        schemas = {
            "network_traffic": {
                "1.0.0": {
                    "icmp": {
                        "data_stream.dataset": "constant_keyword",
                        "destination.ip": "ip",
                        "network_traffic.icmp.request.type": "long",
                    },
                }
            }
        }
        manifests = {"network_traffic": {"1.0.0": _manifest("^9.0.0")}}
        data = SimpleNamespace(get=lambda key, default=None: False if key == "notify" else default)
        with (
            unittest.mock.patch("detection_rules.integrations.load_integrations_manifests", return_value=manifests),
            unittest.mock.patch("detection_rules.integrations.load_integrations_schemas", return_value=schemas),
        ):
            schema, package_version = get_integration_schema_fields(
                "network_traffic", "icmp", Version.parse("9.0.0"), data
            )

        self.assertEqual(package_version, "1.0.0")
        self.assertEqual(set(schema), {"data_stream.dataset", "destination.ip", "network_traffic.icmp.request.type"})
        # process.title is a valid ECS field the data stream does not declare
        self.assertNotIn("process.title", schema)


class TestParseVersionSchema(unittest.TestCase):
    """Package field files plus the Elastic Agent fields make up a data stream's cached schema."""

    @staticmethod
    def _package_zip(files: dict[str, str]) -> zipfile.ZipFile:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zip_ref:
            for name, contents in files.items():
                zip_ref.writestr(name, yaml.safe_dump(contents))
        return zipfile.ZipFile(buffer)

    def test_elastic_agent_fields_are_derived_from_ecs(self):
        """The agent, cloud and host ECS sets, the data_stream constant keywords and the Fleet pipeline fields."""
        fields = elastic_agent_fields()

        for name, field_type in {
            "agent.id": "keyword",
            "host.name": "keyword",
            "host.ip": "ip",
            "host.os.type": "keyword",
            "host.os.name.text": "match_only_text",
            "cloud.provider": "keyword",
            "data_stream.dataset": "constant_keyword",
            "event.agent_id_status": "keyword",
            "event.ingested": "date",
        }.items():
            self.assertEqual(fields.get(name), field_type, name)
        # field sets ECS re-nests under host/cloud and the origin/target self-nestings are not shipped by Agent
        for name in (
            "host.geo.city_name",
            "host.risk.calculated_level",
            "cloud.origin.provider",
            "cloud.target.region",
        ):
            self.assertNotIn(name, fields)
        self.assertTrue(
            all(name.startswith(("agent.", "cloud.", "host.", "data_stream.", "event.")) for name in fields), fields
        )

    def test_every_data_stream_gets_agent_fields_and_declared_fields_win(self):
        zip_ref = self._package_zip(
            {
                "pkg-1.0.0/data_stream/ds/fields/ecs.yml": [
                    {"name": "destination.ip", "type": "ip"},
                    {"name": "agent.id", "type": "wildcard"},
                    # built packages resolve `external: ecs` into explicit multi_fields, which are mapped too
                    {
                        "name": "process.name",
                        "type": "keyword",
                        "multi_fields": [{"name": "text", "type": "match_only_text"}],
                    },
                ],
                "pkg-1.0.0/data_stream/plain/fields/fields.yml": [{"name": "pkg.y", "type": "keyword"}],
            }
        )

        version_schema = parse_version_schema(zip_ref, "pkg")

        self.assertEqual(set(version_schema), {"ds", "plain"})
        self.assertEqual(version_schema["ds"]["destination.ip"], "ip")
        self.assertEqual(version_schema["ds"]["agent.id"], "wildcard")
        self.assertEqual(version_schema["ds"]["process.name.text"], "match_only_text")
        self.assertEqual(version_schema["ds"]["event.ingested"], "date")
        self.assertEqual(version_schema["plain"]["pkg.y"], "keyword")
        self.assertEqual(version_schema["plain"]["agent.id"], "keyword")
        self.assertEqual(version_schema["plain"]["data_stream.dataset"], "constant_keyword")
        # undeclared ECS fields are not part of the schema
        self.assertNotIn("process.title", version_schema["ds"])

    def test_committed_cache_was_built_by_parse_version_schema(self):
        """Every cached data stream carries the Agent fields and nothing but field schemas (and ML job lists)."""
        for package, versions in load_integrations_schemas().items():
            version = sorted(versions, key=Version.parse)[-1]
            for name, stream in versions[version].items():
                if name == "jobs":
                    continue
                self.assertIn("data_stream.dataset", stream, f"{package} {version} {name}")
                self.assertIn("agent.id", stream, f"{package} {version} {name}")


class TestEsqlIndexCoverage(unittest.TestCase):
    """Full ECS is omitted only when every FROM index belongs to a rule integration."""

    def test_non_integration_indices_keep_full_ecs(self):
        from detection_rules.esql import EventDataset
        from detection_rules.index_mappings import esql_indices_covered_by_packages

        eds = [EventDataset("pkg", "audit")]
        self.assertTrue(esql_indices_covered_by_packages(["logs-pkg.audit-*"], [], eds))
        self.assertTrue(esql_indices_covered_by_packages(["logs-pkg*"], ["pkg"], []))
        self.assertTrue(esql_indices_covered_by_packages(["metrics-system.cpu-*"], ["system"], []))
        self.assertTrue(esql_indices_covered_by_packages(["traces-apm.span-*"], ["apm"], []))
        # Beats, broad metrics, and unrelated indices are not one integration stream
        self.assertFalse(esql_indices_covered_by_packages(["logs-pkg.audit-*", "auditbeat-*"], [], eds))
        self.assertFalse(esql_indices_covered_by_packages(["logs-other.stream-*"], [], eds))
        self.assertFalse(esql_indices_covered_by_packages(["metrics-*"], ["system"], []))
        self.assertFalse(esql_indices_covered_by_packages(["metrics-system.cpu-*"], ["aws"], []))
        # nothing extracted from FROM must not pass vacuously
        self.assertFalse(esql_indices_covered_by_packages([], ["pkg"], []))

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test integration version resolution against EPR manifest ranges."""

import os
import unittest
import unittest.mock

from semver import Version

from detection_rules.config import load_current_package_version
from detection_rules.integrations import (
    _MAX_UNBOUNDED_STACK_MAJOR_SPAN,
    STACK_INVARIANT_INTEGRATION_VERSION_RANGES_ENV,
    _find_least_compatible_for_stack,
    _majors_overlapping_kibana_clause,
    _parse_clause,
    _parse_kibana_range,
    _satisfies_kibana_range,
    _stack_majors_supported_by_package,
    find_compatible_version_range,
    find_latest_compatible_version,
    find_latest_integration_patch_for_minor,
)
from detection_rules.rule_validators import KQLValidator
from detection_rules.schemas import get_stack_versions


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
        """Clauses separated by ``||`` are returned as a list of OR'd ranges."""
        self.assertEqual(
            _parse_kibana_range("^8.12.0 || ^9.0.0"),
            [
                (Version(8, 12, 0), Version(9, 0, 0)),
                (Version(9, 0, 0), Version(10, 0, 0)),
            ],
        )

    def test_mixed_and_or(self):
        """AND'd tokens inside each clause and OR'd clauses compose correctly."""
        self.assertEqual(
            _parse_kibana_range(">=8.12.0 <9.0.0 || ^9.1.0"),
            [
                (Version(8, 12, 0), Version(9, 0, 0)),
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

    def test_or_union(self):
        """OR'd clauses accept stacks inside either clause and reject otherwise."""
        self.assertTrue(_satisfies_kibana_range(Version(8, 12, 5), "^8.12.0 || ^9.0.0"))
        self.assertTrue(_satisfies_kibana_range(Version(9, 0, 1), "^8.12.0 || ^9.0.0"))
        self.assertFalse(_satisfies_kibana_range(Version(10, 0, 0), "^8.12.0 || ^9.0.0"))

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

    def test_or_clause_match(self):
        """A stack that falls in any OR'd sub-range is considered compatible."""
        manifests = {"pkg": {"1.0.0": _manifest("^8.12.0 || ^9.0.0")}}
        version, _ = find_latest_compatible_version("pkg", "pkg", Version(8, 15, 0), manifests)
        self.assertEqual(version, "1.0.0")

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
                newer_version: _manifest(
                    f"~{current_version.major}.{current_version.minor}.{required_patch} || "
                    f"^{current_version.major}.{current_version.minor + 1}.0"
                ),
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
                "1.1.0": _manifest(
                    f"~{current_version.major}.{current_version.minor}.{required_patch} || "
                    f"^{current_version.major}.{current_version.minor + 1}.0"
                ),
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


class TestFindCompatibleVersionRangeEnvGate(unittest.TestCase):
    """Env-gated behavior for related integration version population."""

    def test_default_uses_current_stack_single_anchor(self):
        """Without the env var, related integrations keep the current-stack single caret range."""
        manifests = {
            "pkg": {
                "1.0.0": _manifest("^8.0.0"),
                "2.0.0": _manifest("^9.0.0"),
            }
        }
        current_stack = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
        expected = _find_least_compatible_for_stack(current_stack, manifests["pkg"])
        self.assertIsNotNone(expected)

        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(STACK_INVARIANT_INTEGRATION_VERSION_RANGES_ENV, None)
            result = find_compatible_version_range("pkg", manifests)

        self.assertEqual(result.range, f"^{expected}")
        self.assertEqual(result.anchors, (expected,))
        self.assertEqual(result.forward_anchor, "")

    def test_env_var_enables_stack_invariant_or_range(self):
        """The env var opts in to one anchor per shipped stack major plus the forward anchor."""
        manifests = {
            "pkg": {
                "1.0.0": _manifest("^8.0.0"),
                "2.0.0": _manifest("^9.0.0"),
            }
        }
        with unittest.mock.patch.dict(os.environ, {STACK_INVARIANT_INTEGRATION_VERSION_RANGES_ENV: "1"}):
            result = find_compatible_version_range("pkg", manifests)

        self.assertEqual(result.range, "^1.0.0 || ^2.0.0 || ^3.0.0")
        self.assertEqual(result.anchors, ("1.0.0", "2.0.0"))
        self.assertEqual(result.forward_anchor, "3.0.0")


@unittest.mock.patch.dict(os.environ, {STACK_INVARIANT_INTEGRATION_VERSION_RANGES_ENV: "1"})
class TestFindCompatibleVersionRange(unittest.TestCase):
    """Behavior coverage for ``find_compatible_version_range``."""

    def test_emits_or_range_across_majors(self):
        """Emits oldest anchor per shipped stack major plus a forward-looking next-major anchor."""
        manifests = {
            "pkg": {
                "1.0.0": _manifest("^8.0.0"),
                "1.5.0": _manifest("^8.0.0"),
                "2.0.0": _manifest("^9.0.0"),
                "2.5.0": _manifest("^9.1.0"),
            }
        }
        result = find_compatible_version_range("pkg", manifests)
        self.assertEqual(result.range, "^1.0.0 || ^2.0.0 || ^3.0.0")
        self.assertEqual(result.anchors, ("1.0.0", "2.0.0"))
        self.assertEqual(result.forward_anchor, "3.0.0")

    def test_stack_invariance(self):
        """Range result does not depend on build stack version."""
        manifests = {
            "pkg": {
                "1.0.0": _manifest("^8.0.0"),
                "2.0.0": _manifest("^9.0.0"),
            }
        }
        first = find_compatible_version_range("pkg", manifests)
        second = find_compatible_version_range("pkg", manifests)
        self.assertEqual(first, second)

    def test_single_major_appends_forward_anchor(self):
        """A single integration major still appends the forward-looking anchor."""
        manifests = {"pkg": {"9.0.0": _manifest("^9.0.0")}}
        result = find_compatible_version_range("pkg", manifests)
        self.assertEqual(result.range, "^9.0.0 || ^10.0.0")
        self.assertEqual(result.anchors, ("9.0.0",))
        self.assertEqual(result.forward_anchor, "10.0.0")

    def test_three_majors_endpoint_shape(self):
        """Synthetic endpoint-like majors on shipped stack lines (8.x and 9.x)."""
        manifests = {
            "endpoint": {
                "7.17.0": _manifest("^7.17.0"),
                "8.2.0": _manifest("^8.2.0"),
                "9.0.0": _manifest("^9.0.0"),
            }
        }
        result = find_compatible_version_range("endpoint", manifests)
        self.assertEqual(result.range, "^8.2.0 || ^9.0.0 || ^10.0.0")
        self.assertEqual(result.anchors, ("8.2.0", "9.0.0"))
        self.assertEqual(result.forward_anchor, "10.0.0")

    def test_skips_majors_with_no_overlap(self):
        """Majors without stack overlap are omitted from anchors."""
        manifests = {
            "pkg": {
                "7.10.0": _manifest("^7.10.0"),
                "9.4.0": _manifest("=9.4.0"),
            }
        }
        result = find_compatible_version_range("pkg", manifests)
        self.assertEqual(result.range, "^9.4.0 || ^10.0.0")
        self.assertEqual(result.anchors, ("9.4.0",))

    def test_raises_when_no_compatible_major(self):
        """When no stack line can be resolved, raise."""
        manifests = {
            "pkg": {
                "1.0.0": _manifest(">=99.0.0 <99.0.0"),
            }
        }
        with self.assertRaises(ValueError):
            find_compatible_version_range("pkg", manifests)

    def test_returns_anchor_list_for_policy_template_lookup(self):
        """Anchors and forward anchor are exposed for policy template union."""
        manifests = {
            "pkg": {
                "1.0.0": _manifest("^8.0.0"),
                "2.0.0": _manifest("^9.0.0"),
            }
        }
        result = find_compatible_version_range("pkg", manifests)
        self.assertEqual(result.anchors, ("1.0.0", "2.0.0"))
        self.assertEqual(result.forward_anchor, "3.0.0")

    def test_unbounded_kibana_range_collects_multiple_stack_majors(self):
        """``>=8.12.0`` (unbounded upper) must collect every overlapping stack major."""
        manifests = {"pkg": {"1.0.0": _manifest(">=8.12.0")}}
        stack_majors = _stack_majors_supported_by_package(manifests["pkg"])
        lo_major = 8
        expected = set(range(lo_major, lo_major + _MAX_UNBOUNDED_STACK_MAJOR_SPAN + 1))
        self.assertEqual(stack_majors, expected)

    def test_bounded_kibana_range_includes_upper_major(self):
        """``>=8.12.0 <9.1.0`` overlaps stack major 9 (9.0.x) and must include it."""
        majors = _majors_overlapping_kibana_clause(
            Version(8, 12, 0),
            Version(9, 1, 0),
            ">=8.12.0 <9.1.0",
        )
        self.assertIn(8, majors)
        self.assertIn(9, majors)
        self.assertNotIn(10, majors)

    def test_non_aligned_package_covers_shipped_stack_majors(self):
        """Non-aligned packages emit one anchor per shipped backport stack major."""
        manifests = {
            "pkg": {
                "1.0.0": _manifest("^8.12.0"),
                "1.1.0": _manifest("^9.0.0"),
                "1.2.0": _manifest("^10.0.0"),
            }
        }
        result = find_compatible_version_range("pkg", manifests)
        # Stack 10 is not a shipped backport line; only 8.x and 9.x majors from stack-schema-map.
        self.assertEqual(result.anchors, ("1.0.0", "1.1.0"))
        self.assertEqual(result.range, "^1.0.0 || ^1.1.0 || ^2.0.0")

    def test_excludes_unshipped_stack_majors(self):
        """Manifest stack lines outside shipped backports (e.g. Kibana 7.x) are not walked."""
        manifests = {
            "pkg": {
                "0.0.2": _manifest("^7.9.0"),
                "1.0.0": _manifest("^8.0.0"),
                "1.22.0": _manifest("^9.0.0"),
            }
        }
        result = find_compatible_version_range("pkg", manifests)
        self.assertEqual(result.anchors, ("1.0.0", "1.22.0"))
        self.assertNotIn("0.0.2", result.anchors)
        self.assertEqual(result.range, "^1.0.0 || ^1.22.0 || ^2.0.0")

    def test_keeps_zero_major_when_only_stable_option_missing(self):
        """Keep 0.x anchors when no major >= 1 anchor exists."""
        manifests = {"pkg": {"0.5.0": _manifest("^8.0.0")}}
        result = find_compatible_version_range("pkg", manifests)
        self.assertEqual(result.anchors, ("0.5.0",))

    def test_anchors_cover_each_shipped_stack_export(self):
        """Each per-stack least-compatible anchor must appear in the OR range (Kibana semver.satisfies)."""
        manifests = {
            "pkg": {
                "1.0.0": _manifest("^8.0.0"),
                "2.0.0": _manifest("^9.2.0"),
                "3.0.0": _manifest("^9.4.0"),
            }
        }
        result = find_compatible_version_range("pkg", manifests)
        for stack_version_str in get_stack_versions():
            stack_version = Version.parse(stack_version_str)
            expected = _find_least_compatible_for_stack(stack_version, manifests["pkg"])
            if expected is None:
                continue
            self.assertIn(
                expected,
                result.anchors,
                f"stack {stack_version_str} exported ^{expected} but anchors are {result.anchors}",
            )

    def test_aws_range_includes_late_stack_anchors(self):
        """AWS 5.x/6.x require Kibana ^9.2+; walking 9.0.0 per major missed them."""
        from detection_rules.integrations import load_integrations_manifests

        manifests = load_integrations_manifests()
        result = find_compatible_version_range("aws", manifests)
        self.assertIn("5.0.0", result.anchors)
        self.assertIn("6.0.0", result.anchors)
        self.assertNotIn("1.5.0", result.anchors)
        for stack_version_str in get_stack_versions():
            stack_version = Version.parse(stack_version_str)
            expected = _find_least_compatible_for_stack(stack_version, manifests["aws"])
            self.assertIsNotNone(expected)
            self.assertIn(expected, result.anchors, stack_version_str)


@unittest.mock.patch.dict(os.environ, {STACK_INVARIANT_INTEGRATION_VERSION_RANGES_ENV: "1"})
class TestFindCompatibleVersionRangeSchemaAware(unittest.TestCase):
    """Schema-aware data stream filtering ported from #6251 into OR-range export."""

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
        with unittest.mock.patch("detection_rules.integrations.load_integrations_schemas", return_value=schemas):
            new_ds = find_compatible_version_range("pkg", manifests, integration="new_ds")
            self.assertIn("1.9.0", new_ds.anchors)
            self.assertNotIn("1.0.0", new_ds.anchors)
            self.assertNotIn("1.5.0", new_ds.anchors)

            existing_ds = find_compatible_version_range("pkg", manifests, integration="existing_ds")
            self.assertEqual(existing_ds.anchors, ("1.0.0",))

    def test_no_schema_data_falls_back_to_kibana_only(self):
        """Versions without schema data are not filtered; kibana compatibility alone decides."""
        manifests = {"pkg": {"1.0.0": _manifest("^8.12.0"), "1.5.0": _manifest("^8.12.0")}}
        with unittest.mock.patch("detection_rules.integrations.load_integrations_schemas", return_value={}):
            result = find_compatible_version_range("pkg", manifests, integration="new_ds")
            self.assertEqual(result.anchors, ("1.0.0",))

    def test_all_compatible_versions_missing_integration_raises(self):
        """Raise when every kibana-compatible version's schema lacks the requested integration."""
        manifests = {"pkg": {"1.0.0": _manifest("^8.12.0"), "1.5.0": _manifest("^8.12.0")}}
        schemas = {"pkg": {"1.0.0": {"existing_ds": {}}, "1.5.0": {"existing_ds": {}}}}
        with (
            unittest.mock.patch("detection_rules.integrations.load_integrations_schemas", return_value=schemas),
            self.assertRaises(ValueError),
        ):
            find_compatible_version_range("pkg", manifests, integration="new_ds")

    def test_schema_floor_excludes_legacy_zero_major(self):
        """Schema-floor fallback must not retain 0.x anchors from the package baseline."""
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
        with unittest.mock.patch("detection_rules.integrations.load_integrations_schemas", return_value=schemas):
            result = find_compatible_version_range("pkg", manifests, integration="aadgraphactivitylogs")
            self.assertEqual(result.anchors, ("1.37.0",))
            self.assertEqual(result.range, "^1.37.0 || ^2.0.0")

    def test_azure_aadgraphactivitylogs_schema_floor(self):
        """aadgraphactivitylogs floor is azure 1.37.0 (bundled integration-schemas.json.gz)."""
        from detection_rules.integrations import load_integrations_manifests, load_integrations_schemas

        schemas = load_integrations_schemas()
        manifests = load_integrations_manifests()
        result = find_compatible_version_range("azure", manifests, integration="aadgraphactivitylogs")
        self.assertIn("1.37.0", result.anchors)
        self.assertNotIn("1.0.0", result.anchors)
        self.assertNotIn("0.0.2", result.anchors)
        self.assertIn("^1.37.0", result.range)
        self.assertEqual(result.range, "^1.37.0 || ^2.0.0")
        floor_versions = [
            version
            for version in sorted(schemas["azure"], key=Version.parse)
            if "aadgraphactivitylogs" in schemas["azure"][version]
        ]
        self.assertEqual(floor_versions[0], "1.37.0")


@unittest.mock.patch.dict(os.environ, {STACK_INVARIANT_INTEGRATION_VERSION_RANGES_ENV: "1"})
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
        self.assertEqual(endpoint_rows[0]["version"], "^8.7.0 || ^9.0.0 || ^10.0.0")
        self.assertEqual(windows_rows[0]["version"], "^1.0.0 || ^3.0.0 || ^4.0.0")


class TestEsqlPackagedIntegrations(unittest.TestCase):
    """ES|QL must not emit a redundant metadata package row when datasets cover the package."""

    def test_metadata_package_row_needed_helper(self):
        from detection_rules.rule import _esql_metadata_package_row_needed

        self.assertFalse(_esql_metadata_package_row_needed("azure", {"azure.signinlogs"}))
        self.assertFalse(_esql_metadata_package_row_needed("aws", {"aws.cloudtrail", "aws.billing"}))
        self.assertTrue(_esql_metadata_package_row_needed("azure", set()))
        self.assertTrue(_esql_metadata_package_row_needed("aws_bedrock", set()))

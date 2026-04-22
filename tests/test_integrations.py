# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test integration version resolution against EPR manifest ranges."""

import unittest

from semver import Version

from detection_rules.integrations import (
    _parse_clause,
    _parse_kibana_range,
    _satisfies_kibana_range,
    find_latest_compatible_version,
    find_least_compatible_version,
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


class TestFindLeastCompatibleVersion(unittest.TestCase):
    """Behavior coverage for ``find_least_compatible_version``."""

    def test_picks_oldest_compatible_in_latest_major(self):
        """Returns the oldest manifest in the latest major whose range admits the stack."""
        manifests = {
            "pkg": {
                "1.0.0": _manifest("^8.12.0"),
                "1.5.0": _manifest("^8.12.0"),
                "2.0.0": _manifest("^9.0.0"),
                "2.1.0": _manifest("^9.1.0"),
                "2.5.0": _manifest("^9.1.0"),
            }
        }
        # 2.0.0 (^9.0.0) is the oldest 9.x manifest that admits a 9.1.0 stack.
        self.assertEqual(find_least_compatible_version("pkg", "pkg", "9.1.0", manifests), "^2.0.0")

    def test_no_compatible_in_any_major_raises(self):
        """When neither the latest nor any prior major admits the stack, raise."""
        manifests = {
            "pkg": {
                "1.0.0": _manifest("^8.12.0"),
                "2.0.0": _manifest("^9.4.0"),
            }
        }
        with self.assertRaises(ValueError):
            find_least_compatible_version("pkg", "pkg", "9.1.0", manifests)

    def test_cross_major_fallback(self):
        """Falls back to an earlier major when the latest major is incompatible."""
        manifests = {
            "pkg": {
                "1.0.0": _manifest("^8.12.0"),
                "2.0.0": _manifest("^9.4.0"),
            }
        }
        self.assertEqual(find_least_compatible_version("pkg", "pkg", "8.12.0", manifests), "^1.0.0")

    def test_or_clause(self):
        """OR'd clauses are honored by the least-compatible search."""
        manifests = {"pkg": {"1.0.0": _manifest("^8.12.0 || ^9.0.0")}}
        self.assertEqual(find_least_compatible_version("pkg", "pkg", "9.1.0", manifests), "^1.0.0")

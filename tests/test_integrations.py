# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Unit tests for detection_rules.integrations version resolution."""

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
    def test_caret(self):
        lo, hi = _parse_clause("^9.1.0")
        assert lo == Version(9, 1, 0)
        assert hi == Version(10, 0, 0)

    def test_tilde(self):
        lo, hi = _parse_clause("~8.10.0")
        assert lo == Version(8, 10, 0)
        assert hi == Version(8, 11, 0)

    def test_gte(self):
        lo, hi = _parse_clause(">=8.12.0")
        assert lo == Version(8, 12, 0)
        assert hi is None

    def test_gt(self):
        lo, hi = _parse_clause(">8.12.0")
        assert lo == Version(8, 12, 1)
        assert hi is None

    def test_lte(self):
        lo, hi = _parse_clause("<=9.0.0")
        assert lo == Version(0, 0, 0)
        assert hi == Version(9, 0, 1)

    def test_lt(self):
        lo, hi = _parse_clause("<9.0.0")
        assert lo == Version(0, 0, 0)
        assert hi == Version(9, 0, 0)

    def test_eq_explicit(self):
        lo, hi = _parse_clause("=8.12.0")
        assert lo == Version(8, 12, 0)
        assert hi == Version(8, 12, 1)

    def test_bare(self):
        lo, hi = _parse_clause("8.12.0")
        assert lo == Version(8, 12, 0)
        assert hi == Version(8, 12, 1)

    def test_anded_tokens(self):
        lo, hi = _parse_clause(">=8.12.0 <9.0.0")
        assert lo == Version(8, 12, 0)
        assert hi == Version(9, 0, 0)

    def test_caret_on_zero_major_raises(self):
        with self.assertRaises(ValueError):
            _parse_clause("^0.1.0")

    def test_unsupported_token_raises(self):
        with self.assertRaises(ValueError):
            _parse_clause("!9.1.0")


class TestParseKibanaRange(unittest.TestCase):
    def test_single_clause(self):
        clauses = _parse_kibana_range("^9.1.0")
        assert clauses == [(Version(9, 1, 0), Version(10, 0, 0))]

    def test_or_clauses(self):
        clauses = _parse_kibana_range("^8.12.0 || ^9.0.0")
        assert clauses == [
            (Version(8, 12, 0), Version(9, 0, 0)),
            (Version(9, 0, 0), Version(10, 0, 0)),
        ]

    def test_mixed_and_or(self):
        clauses = _parse_kibana_range(">=8.12.0 <9.0.0 || ^9.1.0")
        assert clauses == [
            (Version(8, 12, 0), Version(9, 0, 0)),
            (Version(9, 1, 0), Version(10, 0, 0)),
        ]


class TestSatisfiesKibanaRange(unittest.TestCase):
    def test_caret_matches_same_major(self):
        assert _satisfies_kibana_range(Version(9, 4, 0), "^9.1.0") is True
        assert _satisfies_kibana_range(Version(9, 1, 0), "^9.1.0") is True

    def test_caret_rejects_lower_minor(self):
        assert _satisfies_kibana_range(Version(9, 0, 0), "^9.1.0") is False

    def test_caret_rejects_next_major(self):
        assert _satisfies_kibana_range(Version(10, 0, 0), "^9.1.0") is False

    def test_caret_rejects_prior_major(self):
        # The 9.1 stack must NOT satisfy ^9.4.0 — this is the regression fix.
        assert _satisfies_kibana_range(Version(9, 1, 0), "^9.4.0") is False

    def test_or_union(self):
        assert _satisfies_kibana_range(Version(8, 12, 5), "^8.12.0 || ^9.0.0") is True
        assert _satisfies_kibana_range(Version(9, 0, 1), "^8.12.0 || ^9.0.0") is True
        assert _satisfies_kibana_range(Version(10, 0, 0), "^8.12.0 || ^9.0.0") is False

    def test_anded_bounds(self):
        assert _satisfies_kibana_range(Version(8, 13, 0), ">=8.12.0 <9.0.0") is True
        assert _satisfies_kibana_range(Version(9, 0, 0), ">=8.12.0 <9.0.0") is False


class TestFindLatestCompatibleVersion(unittest.TestCase):
    """Regression + behavior coverage for find_latest_compatible_version."""

    def test_picks_latest_compatible_on_same_major(self):
        manifests = {
            "ded": {
                "1.0.0": _manifest("^8.12.0"),
                "2.0.0": _manifest("^9.0.0"),
                "2.1.0": _manifest("^9.1.0"),
                "3.0.0": _manifest("^9.4.0"),
            }
        }
        version, notice = find_latest_compatible_version("ded", "ded", Version(9, 1, 0), manifests)
        assert version == "2.1.0"
        # A newer manifest (3.0.0) exists but needs 9.4+ — notice should point there.
        assert notice
        assert "3.0.0" in notice[0]
        assert "9.4.0" in notice[1]

    def test_regression_91_does_not_pick_ded_300(self):
        # This is the exact shape that broke 46 ML rules: ded 3.0.0 requires ^9.4.0
        # and must NOT be selected for a 9.1 stack even though both share major=9.
        manifests = {
            "ded": {
                "2.1.0": _manifest("^9.1.0"),
                "3.0.0": _manifest("^9.4.0"),
            }
        }
        version, _ = find_latest_compatible_version("ded", "ded", Version(9, 1, 0), manifests)
        assert version == "2.1.0"

    def test_exact_match_on_rule_stack(self):
        manifests = {
            "pkg": {
                "1.0.0": _manifest("^9.4.0"),
            }
        }
        version, notice = find_latest_compatible_version("pkg", "pkg", Version(9, 4, 0), manifests)
        assert version == "1.0.0"
        assert notice == [""]

    def test_or_clause_match(self):
        manifests = {
            "pkg": {
                "1.0.0": _manifest("^8.12.0 || ^9.0.0"),
            }
        }
        version, _ = find_latest_compatible_version("pkg", "pkg", Version(8, 15, 0), manifests)
        assert version == "1.0.0"

    def test_no_compatible_version_raises(self):
        manifests = {
            "pkg": {
                "1.0.0": _manifest("^9.4.0"),
            }
        }
        with self.assertRaises(ValueError):
            find_latest_compatible_version("pkg", "pkg", Version(8, 12, 0), manifests)

    def test_missing_conditions_raises(self):
        manifests = {"pkg": {"1.0.0": {"conditions": {}}}}
        with self.assertRaises(ValueError):
            find_latest_compatible_version("pkg", "pkg", Version(9, 1, 0), manifests)

    def test_unknown_package_raises(self):
        with self.assertRaises(ValueError):
            find_latest_compatible_version("missing", "missing", Version(9, 1, 0), {})


class TestFindLeastCompatibleVersion(unittest.TestCase):
    def test_picks_oldest_compatible_in_latest_major(self):
        manifests = {
            "pkg": {
                "1.0.0": _manifest("^8.12.0"),
                "1.5.0": _manifest("^8.12.0"),
                "2.0.0": _manifest("^9.0.0"),
                "2.1.0": _manifest("^9.1.0"),
                "2.5.0": _manifest("^9.1.0"),
            }
        }
        # "Least compatible" == oldest manifest in the latest major whose range
        # satisfies the stack. 2.0.0 (^9.0.0) satisfies 9.1.0 and predates 2.1.0.
        result = find_least_compatible_version("pkg", "pkg", "9.1.0", manifests)
        assert result == "^2.0.0"

    def test_falls_back_to_prior_major(self):
        manifests = {
            "pkg": {
                "1.0.0": _manifest("^8.12.0"),
                "2.0.0": _manifest("^9.4.0"),
            }
        }
        # 9.1 stack can't satisfy 2.0.0 (^9.4.0), but 1.0.0 (^8.12.0) also doesn't apply —
        # so ensure we raise cleanly rather than returning garbage.
        with self.assertRaises(ValueError):
            find_least_compatible_version("pkg", "pkg", "9.1.0", manifests)

    def test_cross_major_fallback(self):
        manifests = {
            "pkg": {
                "1.0.0": _manifest("^8.12.0"),
                "2.0.0": _manifest("^9.4.0"),
            }
        }
        # On an 8.12 stack, the latest-major (2.0.0) isn't compatible, so we fall back
        # to the 8.x major and return the least compatible 8.x.
        result = find_least_compatible_version("pkg", "pkg", "8.12.0", manifests)
        assert result == "^1.0.0"

    def test_or_clause(self):
        manifests = {
            "pkg": {
                "1.0.0": _manifest("^8.12.0 || ^9.0.0"),
            }
        }
        result = find_least_compatible_version("pkg", "pkg", "9.1.0", manifests)
        assert result == "^1.0.0"


if __name__ == "__main__":
    unittest.main()

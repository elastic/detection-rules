# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test version locking of rules."""

import unittest

from semver import Version

from detection_rules.schemas import get_min_supported_stack_version
from detection_rules.version_lock import RULES_CONFIG, loaded_version_lock


class TestVersionLock(unittest.TestCase):
    """Test version locking."""

    @unittest.skipIf(RULES_CONFIG.bypass_version_lock, "Version lock bypassed")
    def test_previous_entries_gte_current_min_stack(self):
        """Test that all previous entries for all locks in the version lock are >= the current min_stack."""
        errors = {}
        min_version = get_min_supported_stack_version()
        for rule_id, lock in loaded_version_lock.version_lock.to_dict().items():
            if "previous" in lock:
                prev_vers = [Version.parse(v, optional_minor_and_patch=True) for v in list(lock["previous"])]
                outdated = [f"{v.major}.{v.minor}" for v in prev_vers if v < min_version]
                if outdated:
                    errors[rule_id] = outdated

        # This should only ever happen when bumping the backport matrix support up, which is based on the
        # stack-schema-map
        if errors:
            err_str = "\n".join(f"{k}: {', '.join(v)}" for k, v in errors.items())
            self.fail(
                f"The following version.lock entries have previous locked versions which are lower than the "
                f"currently supported min_stack ({min_version}). To address this, run the "
                f"`dev trim-version-lock {min_version}` command.\n\n{err_str}"
            )


class TestShippedVersionFloor(unittest.TestCase):
    """A rule_id + version pair shipped through any lock channel must never be reused."""

    def test_floor_moves_baseline_past_dropped_epoch_version(self):
        """Baseline bumped to 4 while the epoch being dropped shipped 4 -> baseline becomes 5."""
        from detection_rules.version_lock import floor_baseline_past_dropped_epoch, max_shipped_emit_version

        entry = {
            "rule_name": "x",
            "sha256": "a" * 64,
            "type": "query",
            "version": 4,
            "stack_emit": {"9.5": {"sha256": "b" * 64, "version": 4, "transforms": ["mitre_attack_v19"]}},
        }
        self.assertEqual(max_shipped_emit_version(entry), 4)
        self.assertEqual(floor_baseline_past_dropped_epoch(entry, 4), 5)
        self.assertEqual(entry["version"], 5)

    def test_floor_is_noop_when_baseline_already_above(self):
        """A baseline above the dropped emit version is left untouched."""
        from detection_rules.version_lock import floor_baseline_past_dropped_epoch

        entry = {"version": 10}
        self.assertEqual(floor_baseline_past_dropped_epoch(entry, 4), 10)
        self.assertEqual(entry["version"], 10)

    def test_double_bump_check_understands_shipped_emit_versions(self):
        """3 -> 5 is a normal step when emit shipped 4; 3 -> 5 with no emit channel is still a double bump."""
        from detection_rules.utils import check_double_bumps, compare_versions

        base = {"r": {"rule_name": "x", "version": 3, "stack_emit": {"9.5": {"sha256": "b" * 64, "version": 4}}}}
        branch = {"r": {"rule_name": "x", "version": 5}}
        changes = compare_versions(base, branch)
        self.assertEqual(changes, [("r", "x", 4, 5)])
        self.assertEqual(check_double_bumps(changes), [])

        plain_changes = compare_versions({"r": {"rule_name": "x", "version": 3}}, branch)
        self.assertEqual(check_double_bumps(plain_changes), [("r", "x", 3, 5)])

    def test_add_historical_rules_reports_same_version_content_drift(self):
        """A previous-package asset with the same version but different content is reported, not silently kept."""
        import json
        import tempfile
        from pathlib import Path
        from unittest import mock

        from detection_rules.packaging import Package

        with tempfile.TemporaryDirectory() as tmp:
            release = Path(tmp)
            rules_dir = release / "fleet" / "9.5.9" / "kibana" / "security_rule"
            rules_dir.mkdir(parents=True)
            current = {"attributes": {"rule_id": "rid", "version": 4, "name": "n", "query": "new", "tags": ["a"]}}
            (rules_dir / "rid_4.json").write_text(json.dumps(current))
            historical = {
                "rid_3": {"attributes": {"rule_id": "rid", "version": 3, "name": "n", "query": "v3", "tags": ["a"]}},
                "rid_4": {"attributes": {"rule_id": "rid", "version": 4, "name": "n", "query": "old", "tags": []}},
            }
            with mock.patch("detection_rules.packaging.CURRENT_RELEASE_PATH", release):
                drifts = Package.add_historical_rules(historical, "9.5.9")
            self.assertTrue((rules_dir / "rid_3.json").exists())  # historical v3 written as before
            self.assertEqual(json.loads((rules_dir / "rid_4.json").read_text()), current)  # current v4 untouched

        self.assertEqual(len(drifts), 1)
        self.assertEqual(drifts[0]["rule_id"], "rid")
        self.assertEqual(drifts[0]["version"], 4)
        self.assertEqual(drifts[0]["fields"], ["query", "tags"])

    @unittest.skipIf(RULES_CONFIG.bypass_version_lock, "Version lock bypassed")
    def test_manage_versions_route_a_skips_shipped_emit_version(self):
        """Replay of issue #7012: baseline 3 + stack_emit 4, rule tuned -> baseline 5, not 4."""
        import json
        import tempfile
        from pathlib import Path
        from unittest import mock

        from detection_rules.rule_loader import RuleCollection
        from detection_rules.version_lock import VersionLock

        rule_path = Path("rules/integrations/azure/privilege_escalation_azure_rbac_administrator_roles_assigned.toml")
        rule = RuleCollection().load_file(rule_path)  # only to read id / name / type for the lock entry
        lock_entry = {
            "rule_name": rule.name,
            "sha256": "0" * 64,  # anything but the real hash: the rule is "tuned"
            "type": rule.contents.type,
            "version": 3,
            "stack_emit": {
                "9.5": {
                    "sha256": "1" * 64,
                    "version": 4,
                    "transforms": ["mitre_attack_v19", "related_integrations_gte"],
                }
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "version.lock.json"
            dep_path = Path(tmp) / "deprecated_rules.json"
            lock_path.write_text(json.dumps({rule.id: lock_entry}))
            dep_path.write_text("{}")
            lock = VersionLock(lock_path, dep_path, name="test")

            # `version_lock` on rule contents is a cached_property, so the lock has to be in place before the
            # rule is loaded (the collection hands it to every rule it loads); patching the global alone is not
            # enough once another test has touched the property on a cached contents object.
            rc = RuleCollection()
            rc._version_lock = lock  # noqa: SLF001
            rule = rc.load_file(rule_path)
            rule.contents.__dict__.pop("version_lock", None)

            with mock.patch("detection_rules.rule.loaded_version_lock", lock):
                self.assertIs(rule.contents.version_lock, lock)
                self.assertTrue(rule.contents.is_dirty)
                self.assertEqual(rule.contents.autobumped_version, 4)  # the pre-fix number

                changed, _, _ = lock.manage_versions(rc, save_changes=True, verbose=False)
            saved = json.loads(lock_path.read_text())[rule.id]

        self.assertIn(rule.id, changed)
        self.assertGreaterEqual(saved["version"], 5)
        for emit in (saved.get("stack_emit") or {}).values():
            self.assertGreater(emit["version"], saved["version"])

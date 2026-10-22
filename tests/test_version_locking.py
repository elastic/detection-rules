# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test version locking of rules."""

import json
import shutil
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

from semver import Version

from detection_rules.config import load_current_package_version
from detection_rules.rule_loader import RuleCollection
from detection_rules.schemas import get_min_supported_stack_version
from detection_rules.stack_emit import emit_epoch_key, parse_stack
from detection_rules.utils import check_double_bumps, check_reused_versions, compare_versions
from detection_rules.version_lock import RULES_CONFIG, VersionLock, loaded_version_lock, next_version


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


class TestNextVersion(unittest.TestCase):
    """Test that a version shipped through any lock channel is never handed out again."""

    def test_unforked_rule_clears_its_epoch(self):
        """Azure RBAC before the collision: baseline 3, 9.5 epoch shipped 4. Next must be 5, not 4."""
        entry = {"version": 3, "stack_emit": {"9.5": {"version": 4, "sha256": "a" * 64, "transforms": ["x"]}}}
        self.assertEqual(next_version(entry, "9.5"), 5)
        self.assertEqual(next_version(entry, None), 5)

    def test_unforked_rule_without_epoch_is_a_plain_bump(self):
        """An unforked rule without an epoch is a plain bump."""
        self.assertEqual(next_version({"version": 3}, "9.5"), 4)

    def test_fork_ignores_epochs_that_ship_for_newer_stacks(self):
        """The shape of forked rules on main: fork 8.19 at 5 (max 104), top-level 9.4 at 107, epoch 9.5 at 108."""
        entry = {
            "version": 107,
            "min_stack_version": "9.4",
            "previous": {"8.19": {"version": 5, "max_allowable_version": 104}},
            "stack_emit": {"9.5": {"version": 108, "sha256": "a" * 64, "transforms": ["x"]}},
        }
        self.assertEqual(next_version(entry, "8.19"), 6)  # the fork never sees 108
        self.assertEqual(next_version(entry, "9.4"), 109)  # the top-level entry does

    def test_fork_counts_the_epoch_that_ships_for_its_own_stack(self):
        """A forked rule at 9.5 whose 9.5 epoch shipped 7 must bump to 8, inside its range."""
        entry = {
            "version": 107,
            "min_stack_version": "9.6",
            "previous": {"9.5": {"version": 6, "max_allowable_version": 104}},
            "stack_emit": {
                "9.5": {"version": 7, "sha256": "a" * 64, "transforms": ["x"]},
                "9.6": {"version": 108, "sha256": "b" * 64, "transforms": ["x", "y"]},
            },
        }
        self.assertEqual(next_version(entry, "9.5"), 8)
        self.assertEqual(next_version(entry, "9.6"), 109)


class TestManageVersionsRoute(unittest.TestCase):
    """Test that a version shipped through any lock channel is never handed out again with an actual rule file."""

    RULE = Path("rules/integrations/azure/privilege_escalation_azure_rbac_administrator_roles_assigned.toml")

    def setUp(self):
        # the collision needs a stack_emit epoch; 8.19 / 9.3 / 9.4 checkouts have no transforms and no epoch
        if emit_epoch_key(parse_stack(load_current_package_version())) is None:
            self.skipTest("no stack_emit epoch applies to this checkout's package stack")
        self.toml = tomllib.loads(self.RULE.read_text())["rule"]
        self.lock_entry = {
            "rule_name": self.toml["name"],
            "sha256": "0" * 64,  # not the real hash: the rule counts as tuned
            "type": self.toml["type"],
            "version": 3,
            "stack_emit": {"9.5": {"sha256": "1" * 64, "version": 4, "transforms": ["mitre_attack_v19"]}},
        }

    def run_lock(self, **kwargs: bool) -> dict:
        """Run manage_versions over a temp lock holding only the rule's entry; return the saved entry."""
        with tempfile.TemporaryDirectory() as tmp:
            lock_path, dep_path = Path(tmp) / "version.lock.json", Path(tmp) / "deprecated_rules.json"
            lock_path.write_text(json.dumps({self.toml["rule_id"]: self.lock_entry}))
            dep_path.write_text("{}")
            lock = VersionLock(lock_path, dep_path, name="test")
            # a copy, so the default collection's shared rule object never binds to this temporary lock
            rule_copy = Path(tmp) / self.RULE.name
            shutil.copy(self.RULE, rule_copy)
            rc = RuleCollection()
            rc._version_lock = lock  # noqa: SLF001
            rc.load_file(rule_copy)
            with mock.patch("detection_rules.rule.loaded_version_lock", lock):
                lock.manage_versions(rc, save_changes=True, verbose=False, **kwargs)
            return json.loads(lock_path.read_text())[self.toml["rule_id"]]

    def test_tuned_rule_skips_the_version_its_epoch_shipped(self):
        saved = self.run_lock()
        self.assertEqual(saved["version"], 5)  # was 4: the number the rule had already shipped
        self.assertEqual(saved["stack_emit"]["9.5"]["version"], 4)  # the 9.5 epoch had already shipped

    def test_hash_only_run_never_drops_an_epoch(self):
        """Command dev update-lock-versions cannot bump, so it must not drop a no-op epoch (its stacks would ship the baseline)."""
        # the rule content already carries what the transforms would add, so this checkout's epoch is a no-op
        key = emit_epoch_key(parse_stack(load_current_package_version()))
        self.lock_entry["stack_emit"] = {key: {"sha256": "2" * 64, "version": 4, "transforms": ["mitre_attack_v19"]}}
        saved = self.run_lock(exclude_version_update=True)
        self.assertEqual(saved["version"], 3)  # hash-only: no bump
        self.assertEqual(saved["stack_emit"][key]["version"], 4)  # and the no-op epoch is still there
        self.assertNotEqual(saved["sha256"], "0" * 64)  # the hash itself was refreshed

    def test_dropping_a_no_op_epoch_moves_the_baseline_past_what_it_shipped(self):
        """Rule untouched (lock holds its real hash), its epoch became a no-op: the epoch goes, baseline 3 -> 5 not 3."""
        key = emit_epoch_key(parse_stack(load_current_package_version()))
        self.lock_entry["sha256"] = RuleCollection().load_file(self.RULE).contents.get_hash()
        self.lock_entry["stack_emit"] = {key: {"sha256": "2" * 64, "version": 4, "transforms": ["mitre_attack_v19"]}}
        saved = self.run_lock()
        self.assertNotIn("stack_emit", saved)  # the no-op epoch was dropped
        self.assertEqual(saved["version"], 5)  # these stacks ship the baseline now; 4 is the number the epoch shipped


class TestCheckVersionLock(unittest.TestCase):
    """The lock PR check (dev check-version-lock) on a base lock and a branch lock."""

    def entry(self, version: int, sha: str, epoch: int | None = None) -> dict:
        lock = {"rule_name": "r", "sha256": sha * 64, "type": "query", "version": version}
        if epoch is not None:
            lock["stack_emit"] = {"9.5": {"sha256": "e" * 64, "version": epoch, "transforms": ["mitre_attack_v19"]}}
        return lock

    def test_bump_is_measured_from_the_highest_shipped_version(self):
        base = {"with_epoch": self.entry(3, "a", epoch=4), "plain": self.entry(3, "a")}
        branch = {"with_epoch": self.entry(5, "b", epoch=6), "plain": self.entry(5, "b")}
        flagged = [rule_id for rule_id, *_ in check_double_bumps(compare_versions(base, branch))]
        self.assertEqual(flagged, ["plain"])  # 3 -> 5 is a double bump only when nothing shipped 4

    def test_a_shipped_version_with_new_content_is_flagged(self):
        base = {"bug": self.entry(3, "a", epoch=4), "fork": self.entry(107, "a", epoch=108)}
        branch = {
            "bug": self.entry(4, "b", epoch=5),  # the #7012 bug: baseline takes 4, which 9.5 already shipped
            "fork": {**self.entry(207, "b", epoch=208), "previous": {"9.4": self.entry(107, "a")}},  # route B copy
        }
        self.assertEqual(check_reused_versions(base, branch), [("bug", "r", "version", 4)])

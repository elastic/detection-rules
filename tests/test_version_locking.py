# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test version locking of rules."""

import unittest

from semver import Version

from detection_rules.schemas import get_min_supported_stack_version
from detection_rules.utils import next_version
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


class TestNextVersion(unittest.TestCase):
    """Test that a version already shipped for a stack version is never handed out again."""

    def test_unforked_rule_clears_its_epoch(self):
        """A rule baseline at 3 with a stack_emit epoch that shipped 4 must bump to 5."""
        entry = {"version": 3, "stack_emit": {"9.5": {"version": 4, "sha256": "a" * 64, "transforms": ["x"]}}}
        self.assertEqual(next_version(entry, "9.5"), 5)
        self.assertEqual(next_version(entry, None), 5)

    def test_unforked_rule_without_epoch_is_a_plain_bump(self):
        """A rule baseline without an epoch bumps by one."""
        self.assertEqual(next_version({"version": 3}, "9.5"), 4)

    def test_fork_ignores_epochs_that_ship_for_newer_stacks(self):
        """A rule fork bumps from its own version and does not see an epoch that ships for a newer stack."""
        entry = {
            "version": 107,
            "min_stack_version": "9.4",
            "previous": {"8.19": {"version": 5, "max_allowable_version": 104}},
            "stack_emit": {"9.5": {"version": 108, "sha256": "a" * 64, "transforms": ["x"]}},
        }
        self.assertEqual(next_version(entry, "8.19"), 6)
        self.assertEqual(next_version(entry, "9.4"), 109)

    def test_fork_counts_the_epoch_that_ships_for_its_own_stack(self):
        """A rulefork does see an epoch that ships for the stack it serves."""
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


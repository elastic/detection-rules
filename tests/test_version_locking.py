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

    def test_floor_clears_every_epoch_the_baseline_serves(self):
        """Dropping the 9.5 epoch must move the baseline past the retained 9.6 epoch as well: a 9.5-line user
        on the floored baseline who moves to the 9.6 line must not meet the same version with other content."""
        from detection_rules.version_lock import (
            baseline_entry_for_stack,
            emit_versions_for_baseline,
            floor_baseline_past_shipped,
        )

        entry = {
            "rule_name": "x",
            "sha256": "a" * 64,
            "type": "query",
            "version": 4,  # already bumped by route A from 3
            "stack_emit": {
                "9.5": {"sha256": "b" * 64, "version": 4, "transforms": ["mitre_attack_v19"]},
                "9.6": {"sha256": "c" * 64, "version": 5, "transforms": ["mitre_attack_v19", "mitre_atlas"]},
            },
        }
        baseline, stack = baseline_entry_for_stack(entry, "9.5")
        self.assertIs(baseline, entry)
        self.assertIsNone(stack)  # no forks: the top-level entry serves every stack
        shipped = emit_versions_for_baseline(entry, stack)
        self.assertEqual(sorted(shipped), [4, 5])
        self.assertEqual(floor_baseline_past_shipped(baseline, shipped), 6)
        self.assertEqual(entry["version"], 6)

    def test_floor_targets_the_fork_that_ships_the_stack(self):
        """Route C: a rule forked at 9.6 keeps 9.5 under previous["9.5"]; dropping the 9.5 epoch floors that
        fork past the 9.5 epoch only, and leaves the 9.6 top-level entry and epoch alone."""
        from detection_rules.version_lock import (
            baseline_entry_for_stack,
            emit_versions_for_baseline,
            floor_baseline_past_shipped,
        )

        entry = {
            "rule_name": "x",
            "sha256": "a" * 64,
            "type": "query",
            "version": 107,
            "min_stack_version": "9.6",
            "previous": {"9.5": {"version": 6, "max_allowable_version": 104, "sha256": "d" * 64, "type": "query"}},
            "stack_emit": {
                "9.5": {"sha256": "b" * 64, "version": 6, "transforms": ["mitre_attack_v19"]},
                "9.6": {"sha256": "c" * 64, "version": 108, "transforms": ["mitre_attack_v19", "mitre_atlas"]},
            },
        }
        fork, stack = baseline_entry_for_stack(entry, "9.5")
        self.assertIs(fork, entry["previous"]["9.5"])
        self.assertEqual(stack, "9.5")
        self.assertEqual(emit_versions_for_baseline(entry, stack), [6])  # 9.6 epoch is outside the fork's range
        self.assertEqual(floor_baseline_past_shipped(fork, emit_versions_for_baseline(entry, stack)), 7)
        self.assertEqual(entry["previous"]["9.5"]["version"], 7)
        self.assertEqual(entry["version"], 107)

        top, top_stack = baseline_entry_for_stack(entry, "9.6")
        self.assertIs(top, entry)
        self.assertEqual(emit_versions_for_baseline(entry, top_stack), [108])

    def test_inherited_epoch_counts_for_an_unforked_rule_above_its_key(self):
        """9.6 inherits epoch 9.5. An unforked rule with min_stack_version 9.6 ships the top-level entry to 9.6
        packages, which shipped the 9.5 epoch's number, so the floor must clear it."""
        from detection_rules.version_lock import (
            baseline_entry_for_stack,
            emit_versions_for_baseline,
            floor_baseline_past_shipped,
        )

        entry = {
            "version": 4,  # bumped from 3 by route A
            "min_stack_version": "9.6",
            "stack_emit": {"9.5": {"sha256": "b" * 64, "version": 4, "transforms": ["mitre_attack_v19"]}},
        }
        baseline, stack = baseline_entry_for_stack(entry, "9.6")
        self.assertIs(baseline, entry)
        self.assertIsNone(stack)  # unforked: unkeyed, serves every stack
        self.assertEqual(emit_versions_for_baseline(entry, stack), [4])
        self.assertEqual(floor_baseline_past_shipped(baseline, [4]), 5)

        # forked at 9.6 with only a 9.5 epoch: that epoch serves 9.5 and, by inheritance, 9.6, so both the
        # fork and the top-level entry see it
        forked = {
            "version": 107,
            "min_stack_version": "9.6",
            "previous": {"9.5": {"version": 6, "max_allowable_version": 104}},
            "stack_emit": {"9.5": {"sha256": "b" * 64, "version": 7}},
        }
        self.assertEqual(emit_versions_for_baseline(forked, "9.5"), [7])
        self.assertEqual(emit_versions_for_baseline(forked, "9.6"), [7])
        # once a 9.6 epoch exists the 9.5 epoch stops at 9.6
        forked["stack_emit"]["9.6"] = {"sha256": "c" * 64, "version": 108}
        self.assertEqual(emit_versions_for_baseline(forked, "9.5"), [7])
        self.assertEqual(emit_versions_for_baseline(forked, "9.6"), [108])

    def test_floor_refuses_to_leave_a_forks_allowable_range(self):
        """Route C accepted 103 -> 104 with max 104; dropping an epoch that shipped 104 must raise, not write 105
        into the range reserved for the newer baseline."""
        from detection_rules.version_lock import floor_baseline_past_shipped

        fork = {"version": 104, "max_allowable_version": 104}
        with self.assertRaises(ValueError):
            floor_baseline_past_shipped(fork, [104], "rid - name")
        self.assertEqual(fork["version"], 104)  # untouched

    def test_floor_is_noop_when_baseline_already_above(self):
        """A baseline above every shipped emit version is left untouched."""
        from detection_rules.version_lock import floor_baseline_past_shipped

        entry = {"version": 10}
        self.assertEqual(floor_baseline_past_shipped(entry, [4, 5]), 10)
        self.assertEqual(floor_baseline_past_shipped(entry, []), 10)
        self.assertEqual(entry["version"], 10)

    def test_double_bump_check_understands_shipped_emit_versions(self):
        """3 -> 5 is a normal step when emit shipped 4; 3 -> 5 with no emit channel is still a double bump."""
        from detection_rules.utils import check_double_bumps, compare_versions

        base = {"r": {"rule_name": "x", "version": 3, "stack_emit": {"9.5": {"sha256": "b" * 64, "version": 4}}}}
        branch = {"r": {"rule_name": "x", "version": 5}}
        changes = compare_versions(base, branch)
        self.assertEqual(changes, [("r", "x", 4, 5)])
        self.assertEqual(check_double_bumps(changes), [])

        # two epochs, 9.5 dropped: the baseline clears the retained 9.6 epoch too (3 -> 6), measured from 5
        two = {
            "r": {
                "rule_name": "x",
                "version": 3,
                "stack_emit": {"9.5": {"sha256": "b" * 64, "version": 4}, "9.6": {"sha256": "c" * 64, "version": 5}},
            }
        }
        kept = {"r": {"rule_name": "x", "version": 6, "stack_emit": {"9.6": {"sha256": "c" * 64, "version": 5}}}}
        self.assertEqual(check_double_bumps(compare_versions(two, kept)), [])

        plain_changes = compare_versions({"r": {"rule_name": "x", "version": 3}}, branch)
        self.assertEqual(check_double_bumps(plain_changes), [("r", "x", 3, 5)])

        # retained epoch: both channels advanced twice, still a double bump
        retained = {"r": {"rule_name": "x", "version": 5, "stack_emit": {"9.5": {"sha256": "c" * 64, "version": 6}}}}
        self.assertEqual(check_double_bumps(compare_versions(base, retained)), [("r", "x", 3, 5)])

        # dropping an older fork's epoch must not relax the top-level comparison: 107 -> 109 is a double bump
        forked_base = {
            "r": {
                "rule_name": "x",
                "version": 107,
                "min_stack_version": "9.6",
                "previous": {"9.5": {"version": 6, "max_allowable_version": 104}},
                "stack_emit": {"9.5": {"sha256": "b" * 64, "version": 7}, "9.6": {"sha256": "c" * 64, "version": 108}},
            }
        }
        forked_branch = {
            "r": {"rule_name": "x", "version": 109, "stack_emit": {"9.6": {"sha256": "d" * 64, "version": 110}}}
        }
        self.assertEqual(check_double_bumps(compare_versions(forked_base, forked_branch)), [("r", "x", 107, 109)])

        # newest epoch pinned to the baseline (transforms []) while the older one remains: 3 -> 6 is the floor
        pinned = {
            "r": {
                "rule_name": "x",
                "version": 6,
                "stack_emit": {
                    "9.5": {"sha256": "b" * 64, "version": 4, "transforms": ["mitre_attack_v19"]},
                    "9.6": {"sha256": "e" * 64, "version": 6, "transforms": []},
                },
            }
        }
        two["r"]["stack_emit"]["9.5"]["transforms"] = ["mitre_attack_v19"]
        two["r"]["stack_emit"]["9.6"]["transforms"] = ["mitre_attack_v19", "mitre_atlas"]
        self.assertEqual(check_double_bumps(compare_versions(two, pinned)), [])

        # a boundary row added for an epoch that had no row, over an inherited older epoch: 3 -> 5 is the floor
        inherited = {
            "r": {
                "rule_name": "x",
                "version": 3,
                "stack_emit": {"9.5": {"sha256": "b" * 64, "version": 4, "transforms": ["mitre_attack_v19"]}},
            }
        }
        boundary_added = {
            "r": {
                "rule_name": "x",
                "version": 5,
                "stack_emit": {
                    "9.5": {"sha256": "b" * 64, "version": 4, "transforms": ["mitre_attack_v19"]},
                    "9.6": {"sha256": "e" * 64, "version": 5, "transforms": []},
                },
            }
        }
        self.assertEqual(check_double_bumps(compare_versions(inherited, boundary_added)), [])

        # an older fork's epoch turning into a boundary must not relax the top-level comparison
        fork_base = {
            "r": {
                "rule_name": "x",
                "version": 107,
                "min_stack_version": "9.7",
                "previous": {"9.6": {"version": 6, "max_allowable_version": 104}},
                "stack_emit": {
                    "9.6": {"sha256": "b" * 64, "version": 7, "transforms": ["mitre_attack_v19"]},
                    "9.7": {"sha256": "c" * 64, "version": 108, "transforms": ["mitre_attack_v19"]},
                },
            }
        }
        fork_branch = {
            "r": {
                "rule_name": "x",
                "version": 109,
                "min_stack_version": "9.7",
                "previous": {"9.6": {"version": 7, "max_allowable_version": 104}},
                "stack_emit": {
                    "9.6": {"sha256": "d" * 64, "version": 7, "transforms": []},
                    "9.7": {"sha256": "e" * 64, "version": 110, "transforms": ["mitre_attack_v19"]},
                },
            }
        }
        self.assertEqual(check_double_bumps(compare_versions(fork_base, fork_branch)), [("r", "x", 107, 109)])

        # retained epoch, ordinary tuning: baseline 3 -> 4 and emit 4 -> 5 is fine
        tuned = {"r": {"rule_name": "x", "version": 4, "stack_emit": {"9.5": {"sha256": "c" * 64, "version": 5}}}}
        self.assertEqual(check_double_bumps(compare_versions(base, tuned)), [])

    def test_shipped_content_drift_is_found_outside_the_history_retention_limit(self):
        """A published asset with the generated version but different content is reported, even when the
        history copied into the package is trimmed to the latest versions and no longer contains it."""
        import json
        import tempfile
        from pathlib import Path
        from unittest import mock

        from detection_rules.integrations import SecurityDetectionEngine
        from detection_rules.packaging import Package

        def asset(version: int, query: str) -> dict:
            return {"attributes": {"rule_id": "rid", "version": version, "name": "n", "query": query, "tags": ["a"]}}

        with tempfile.TemporaryDirectory() as tmp:
            release = Path(tmp)
            rules_dir = release / "fleet" / "9.5.9" / "kibana" / "security_rule"
            rules_dir.mkdir(parents=True)
            generated = asset(4, "new")
            (rules_dir / "rid_4.json").write_text(json.dumps(generated))
            # the previous package published v4..v7; v4 shipped with different content
            published = {f"rid_{v}": asset(v, "old" if v == 4 else f"v{v}") for v in (4, 5, 6, 7)}
            retained = SecurityDetectionEngine().keep_latest_versions(published, num_versions=3)
            self.assertNotIn("rid_4", retained)  # the colliding version is outside the retention limit

            with mock.patch("detection_rules.packaging.CURRENT_RELEASE_PATH", release):
                drifts = Package.find_shipped_content_drift(published, "9.5.9")
                Package.add_historical_rules(retained, "9.5.9")

            # history copied as before, generated asset untouched
            self.assertEqual(
                sorted(p.name for p in rules_dir.glob("*.json")),
                ["rid_4.json", "rid_5.json", "rid_6.json", "rid_7.json"],
            )
            self.assertEqual(json.loads((rules_dir / "rid_4.json").read_text()), generated)

        self.assertEqual(len(drifts), 1)
        self.assertEqual(drifts[0]["rule_id"], "rid")
        self.assertEqual(drifts[0]["version"], 4)
        self.assertEqual(drifts[0]["fields"], ["query"])

    @unittest.skipIf(RULES_CONFIG.bypass_version_lock, "Version lock bypassed")
    def test_manage_versions_route_a_skips_shipped_emit_version(self):
        """Replay of issue #7012: baseline 3 + stack_emit 4, rule tuned -> baseline 5, not 4."""
        import json
        import shutil
        import tempfile
        import tomllib
        from pathlib import Path
        from unittest import mock

        from detection_rules.config import load_current_package_version
        from detection_rules.rule_loader import RuleCollection
        from detection_rules.stack_emit import emit_epoch_key, parse_stack
        from detection_rules.version_lock import VersionLock

        rule_path = Path("rules/integrations/azure/privilege_escalation_azure_rbac_administrator_roles_assigned.toml")
        toml = tomllib.loads(rule_path.read_text())["rule"]
        lock_entry = {
            "rule_name": toml["name"],
            "sha256": "0" * 64,  # anything but the real hash: the rule is "tuned"
            "type": toml["type"],
            "version": 3,
            "stack_emit": {
                "9.5": {
                    "sha256": "1" * 64,
                    "version": 4,
                    "transforms": ["mitre_attack_v19", "related_integrations_gte"],
                }
            },
        }
        # The collision only exists where an emit epoch applies (package stack 9.5+). On 8.19 / 9.3 / 9.4
        # checkouts no transforms apply, manage_versions never reaches the epoch removal, and the stack
        # cannot be pinned to 9.5 because those branches carry no 9.5 schemas, so the replay is skipped there.
        if emit_epoch_key(parse_stack(load_current_package_version())) is None:
            self.skipTest("no stack_emit epoch applies to this checkout's package stack")

        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "version.lock.json"
            dep_path = Path(tmp) / "deprecated_rules.json"
            lock_path.write_text(json.dumps({toml["rule_id"]: lock_entry}))
            dep_path.write_text("{}")
            lock = VersionLock(lock_path, dep_path, name="test")

            # Load fresh contents from a copy: load_file() hands back the default collection's shared rule
            # object for a known path, and `version_lock` on contents is a cached_property, so a shared
            # object would keep whichever lock it saw first and leak this temporary one to later tests.
            rule_copy = Path(tmp) / rule_path.name
            shutil.copy(rule_path, rule_copy)
            rc = RuleCollection()
            rc._version_lock = lock  # noqa: SLF001  # handed to every rule this collection loads
            rule = rc.load_file(rule_copy)
            self.assertIs(rule.contents.version_lock, lock)

            with mock.patch("detection_rules.rule.loaded_version_lock", lock):
                self.assertTrue(rule.contents.is_dirty)
                self.assertEqual(rule.contents.autobumped_version, 4)  # the pre-fix number

                # a hash-only update (dev update-lock-versions) must not drop the epoch without the bump
                lock.manage_versions(rc, exclude_version_update=True, save_changes=True, verbose=False)
                hash_only = json.loads(lock_path.read_text())[toml["rule_id"]]
                self.assertEqual(hash_only["version"], 3)
                self.assertEqual(hash_only["stack_emit"]["9.5"]["version"], 4)
                self.assertNotEqual(hash_only["sha256"], "0" * 64)  # the hash itself was updated

                # the real lock run drops the epoch and floors the baseline past it
                lock_path.write_text(json.dumps({toml["rule_id"]: lock_entry}))
                lock = VersionLock(lock_path, dep_path, name="test")
                rc = RuleCollection()
                rc._version_lock = lock  # noqa: SLF001
                rule = rc.load_file(rule_copy)
                with mock.patch("detection_rules.rule.loaded_version_lock", lock):
                    changed, _, _ = lock.manage_versions(rc, save_changes=True, verbose=False)
            saved = json.loads(lock_path.read_text())[toml["rule_id"]]

        self.assertIn(rule.id, changed)
        self.assertGreaterEqual(saved["version"], 5)
        self.assertNotIn("stack_emit", saved)

    @unittest.skipIf(RULES_CONFIG.bypass_version_lock, "Version lock bypassed")
    def test_forked_rule_epoch_is_numbered_from_the_fork(self):
        """Route C: a rule whose older stack lives under previous[...] gets its epoch numbered from that fork
        (fork 6 -> 7 on the tuning, epoch 8), never from the top-level entry (107), and inside the fork's
        allowable range; the top-level entry is untouched."""
        import json
        import shutil
        import tempfile
        import tomllib
        from pathlib import Path
        from unittest import mock

        from detection_rules.config import load_current_package_version
        from detection_rules.rule_loader import RuleCollection
        from detection_rules.stack_emit import emit_epoch_key, parse_stack
        from detection_rules.version_lock import VersionLock

        package_epoch = emit_epoch_key(parse_stack(load_current_package_version()))
        if package_epoch is None:
            self.skipTest("no stack_emit epoch applies to this checkout's package stack")

        rule_path = Path("rules/integrations/azure/privilege_escalation_azure_rbac_administrator_roles_assigned.toml")
        text = rule_path.read_text()
        # the fork lives on the package epoch's stack; drop the Persistence tag so the MITRE v19 transform is not
        # a no-op and the epoch gets (re)numbered rather than dropped
        text = text.replace("creation_date = ", f'min_stack_version = "{package_epoch}"\ncreation_date = ', 1)
        text = text.replace('    "Tactic: Persistence",\n', "", 1)
        toml = tomllib.loads(text)
        self.assertEqual(toml["metadata"]["min_stack_version"], package_epoch)
        self.assertNotIn("Tactic: Persistence", toml["rule"]["tags"])

        next_minor = f"{parse_stack(package_epoch).major}.{parse_stack(package_epoch).minor + 1}"
        lock_entry = {
            "rule_name": toml["rule"]["name"],
            "sha256": "a" * 64,
            "type": toml["rule"]["type"],
            "version": 107,
            "min_stack_version": next_minor,  # the top-level entry serves the next stack
            "previous": {
                package_epoch: {
                    "rule_name": toml["rule"]["name"],
                    "sha256": "0" * 64,  # tuned on this fork
                    "type": toml["rule"]["type"],
                    "version": 6,
                    "max_allowable_version": 104,
                }
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "version.lock.json"
            dep_path = Path(tmp) / "deprecated_rules.json"
            lock_path.write_text(json.dumps({toml["rule"]["rule_id"]: lock_entry}))
            dep_path.write_text("{}")
            lock = VersionLock(lock_path, dep_path, name="test")

            rule_copy = Path(tmp) / rule_path.name
            rule_copy.write_text(text)
            rc = RuleCollection()
            rc._version_lock = lock  # noqa: SLF001
            rule = rc.load_file(rule_copy)
            self.assertEqual(rule.contents.saved_version, 6)  # resolved from the fork

            with mock.patch("detection_rules.rule.loaded_version_lock", lock):
                self.assertTrue(rule.contents.is_dirty)
                changed, _, _ = lock.manage_versions(rc, save_changes=True, verbose=False)
            saved = json.loads(lock_path.read_text())[toml["rule"]["rule_id"]]

        self.assertIn(rule.id, changed)
        self.assertEqual(saved["version"], 107)  # top-level entry untouched
        self.assertEqual(saved["previous"][package_epoch]["version"], 7)  # route C bump on the fork
        self.assertEqual(saved["stack_emit"][package_epoch]["version"], 8)  # numbered from the fork, not 108
        shutil.rmtree(tmp, ignore_errors=True)

    @unittest.skipIf(RULES_CONFIG.bypass_version_lock, "Version lock bypassed")
    def test_dropping_the_newest_epoch_pins_its_stacks_to_the_baseline(self):
        """Baseline 3 with 9.5 = 4 and 9.6 = 5. The 9.6 transforms become a no-op: without a 9.6 row the 9.6
        packages would inherit the 9.5 row and the emit-dirty bump would ship v5 again with baseline content.
        The lock must floor the baseline to 6 and pin 9.6 to it with a boundary row, and serialization must
        then ship 6 for 9.6 and report the rule clean. A later tuning refreshes the row to the new baseline."""
        import json
        import shutil
        import tempfile
        import tomllib
        from pathlib import Path
        from unittest import mock

        from detection_rules.config import load_current_package_version
        from detection_rules.rule_loader import RuleCollection
        from detection_rules.stack_emit import parse_stack
        from detection_rules.version_lock import VersionLock

        if parse_stack(load_current_package_version()) < parse_stack("9.6"):
            self.skipTest("models a 9.6 epoch distinct from 9.5; needs a 9.6+ package stack")

        rule_path = Path("rules/integrations/azure/privilege_escalation_azure_rbac_administrator_roles_assigned.toml")
        toml = tomllib.loads(rule_path.read_text())["rule"]
        # the transforms are a no-op for this rule (it already carries its tactic tags); make the package epoch
        # "9.6" so a 9.5 epoch is older than the one being evaluated
        epoch_patches = [
            mock.patch(f"detection_rules.{module}.emit_epoch_key", return_value="9.6")
            for module in ("version_lock", "rule")
        ]

        def load(rc_lock: VersionLock, path: Path):
            rc = RuleCollection()
            rc._version_lock = rc_lock  # noqa: SLF001
            return rc, rc.load_file(path)

        with tempfile.TemporaryDirectory() as tmp:
            rule_copy = Path(tmp) / rule_path.name
            shutil.copy(rule_path, rule_copy)
            lock_path = Path(tmp) / "version.lock.json"
            dep_path = Path(tmp) / "deprecated_rules.json"
            dep_path.write_text("{}")

            # clean baseline (real hash), two real epochs
            probe = RuleCollection().load_file(rule_copy)  # fresh contents; only the hash is needed
            entry = {
                "rule_name": toml["name"],
                "sha256": probe.contents.get_hash(),
                "type": toml["type"],
                "version": 3,
                "stack_emit": {
                    "9.5": {"sha256": "1" * 64, "version": 4, "transforms": ["mitre_attack_v19"]},
                    "9.6": {"sha256": "2" * 64, "version": 5, "transforms": ["mitre_attack_v19", "mitre_atlas"]},
                },
            }
            lock_path.write_text(json.dumps({toml["rule_id"]: entry}))
            lock = VersionLock(lock_path, dep_path, name="test")
            rc, rule = load(lock, rule_copy)
            with epoch_patches[0], epoch_patches[1], mock.patch("detection_rules.rule.loaded_version_lock", lock):
                self.assertFalse(rule.contents.is_dirty)
                self.assertTrue(rule.contents.is_emit_dirty)  # stale real 9.6 epoch for a no-op payload
                lock.manage_versions(rc, save_changes=True, verbose=False)
                saved = json.loads(lock_path.read_text())[toml["rule_id"]]
                self.assertEqual(saved["version"], 6)
                self.assertEqual(saved["stack_emit"]["9.5"]["version"], 4)  # older epoch untouched
                self.assertEqual(saved["stack_emit"]["9.6"]["transforms"], [])
                self.assertEqual(saved["stack_emit"]["9.6"]["version"], 6)
                self.assertEqual(saved["stack_emit"]["9.6"]["sha256"], saved["sha256"])  # mirrors the baseline

                # serialization against the saved lock: 9.6 ships the baseline number and is clean
                relock = VersionLock(lock_path, dep_path, name="test")
                _, rule2 = load(relock, rule_copy)
                with mock.patch("detection_rules.rule.loaded_version_lock", relock):
                    self.assertFalse(rule2.contents.is_emit_dirty)
                    self.assertEqual(rule2.contents.shipped_version, 6)
                    self.assertEqual(rule2.contents.to_api_format()["version"], 6)

    @unittest.skipIf(RULES_CONFIG.bypass_version_lock, "Version lock bypassed")
    def test_boundary_row_follows_the_baseline_on_tuning(self):
        """A boundary row pins its stacks to the baseline, so a tuning that moves the baseline (6 -> 7) must
        refresh the row to 7 with the new untransformed hash, and leave the older epoch alone."""
        import json
        import tempfile
        import tomllib
        from pathlib import Path
        from unittest import mock

        from detection_rules.config import load_current_package_version
        from detection_rules.rule_loader import RuleCollection
        from detection_rules.stack_emit import parse_stack
        from detection_rules.version_lock import VersionLock

        if parse_stack(load_current_package_version()) < parse_stack("9.6"):
            self.skipTest("models a 9.6 epoch distinct from 9.5; needs a 9.6+ package stack")

        rule_path = Path("rules/integrations/azure/privilege_escalation_azure_rbac_administrator_roles_assigned.toml")
        toml = tomllib.loads(rule_path.read_text())["rule"]
        with tempfile.TemporaryDirectory() as tmp:
            rule_copy = Path(tmp) / rule_path.name
            rule_copy.write_text(rule_path.read_text().replace("Resources: Investigation Guide", "Resources: Tuned"))
            lock_path = Path(tmp) / "version.lock.json"
            dep_path = Path(tmp) / "deprecated_rules.json"
            dep_path.write_text("{}")
            entry = {
                "rule_name": toml["name"],
                "sha256": "0" * 64,  # the rule is tuned relative to the lock
                "type": toml["type"],
                "version": 6,
                "stack_emit": {
                    "9.5": {"sha256": "1" * 64, "version": 4, "transforms": ["mitre_attack_v19"]},
                    "9.6": {"sha256": "3" * 64, "version": 6, "transforms": []},  # boundary row, now stale
                },
            }
            lock_path.write_text(json.dumps({toml["rule_id"]: entry}))
            lock = VersionLock(lock_path, dep_path, name="test")
            rc = RuleCollection()
            rc._version_lock = lock  # noqa: SLF001
            rule = rc.load_file(rule_copy)
            with (
                mock.patch("detection_rules.version_lock.emit_epoch_key", return_value="9.6"),
                mock.patch("detection_rules.rule.emit_epoch_key", return_value="9.6"),
                mock.patch("detection_rules.rule.loaded_version_lock", lock),
            ):
                self.assertTrue(rule.contents.is_dirty)
                lock.manage_versions(rc, save_changes=True, verbose=False)
                saved = json.loads(lock_path.read_text())[toml["rule_id"]]
                self.assertEqual(saved["version"], 7)
                self.assertEqual(saved["stack_emit"]["9.5"]["version"], 4)
                self.assertEqual(
                    saved["stack_emit"]["9.6"], {"sha256": saved["sha256"], "version": 7, "transforms": []}
                )

    @unittest.skipIf(RULES_CONFIG.bypass_version_lock, "Version lock bypassed")
    def test_no_op_stack_inheriting_an_older_epoch_gets_a_boundary_row(self):
        """Baseline 3 with only a 9.5 = 4 row. On the 9.6 epoch the transforms are a no-op but 9.6 inherits the
        9.5 row, so it would ship 4 + 1 with baseline content. The lock must floor the baseline past 4 and pin
        9.6 to it."""
        import json
        import shutil
        import tempfile
        import tomllib
        from pathlib import Path
        from unittest import mock

        from detection_rules.config import load_current_package_version
        from detection_rules.rule_loader import RuleCollection
        from detection_rules.stack_emit import parse_stack
        from detection_rules.version_lock import VersionLock

        if parse_stack(load_current_package_version()) < parse_stack("9.6"):
            self.skipTest("models a 9.6 epoch distinct from 9.5; needs a 9.6+ package stack")

        rule_path = Path("rules/integrations/azure/privilege_escalation_azure_rbac_administrator_roles_assigned.toml")
        toml = tomllib.loads(rule_path.read_text())["rule"]
        with tempfile.TemporaryDirectory() as tmp:
            rule_copy = Path(tmp) / rule_path.name
            shutil.copy(rule_path, rule_copy)
            lock_path = Path(tmp) / "version.lock.json"
            dep_path = Path(tmp) / "deprecated_rules.json"
            dep_path.write_text("{}")
            probe = RuleCollection().load_file(rule_copy)  # fresh contents; only the hash is needed
            entry = {
                "rule_name": toml["name"],
                "sha256": probe.contents.get_hash(),
                "type": toml["type"],
                "version": 3,
                "stack_emit": {"9.5": {"sha256": "1" * 64, "version": 4, "transforms": ["mitre_attack_v19"]}},
            }
            lock_path.write_text(json.dumps({toml["rule_id"]: entry}))
            lock = VersionLock(lock_path, dep_path, name="test")
            rc = RuleCollection()
            rc._version_lock = lock  # noqa: SLF001
            rule = rc.load_file(rule_copy)
            with (
                mock.patch("detection_rules.version_lock.emit_epoch_key", return_value="9.6"),
                mock.patch("detection_rules.rule.emit_epoch_key", return_value="9.6"),
                mock.patch("detection_rules.rule.loaded_version_lock", lock),
            ):
                self.assertTrue(rule.contents.is_emit_dirty)  # inherited 9.5 row, no-op payload
                lock.manage_versions(rc, save_changes=True, verbose=False)
                saved = json.loads(lock_path.read_text())[toml["rule_id"]]
                self.assertEqual(saved["version"], 5)
                self.assertEqual(saved["stack_emit"]["9.5"]["version"], 4)
                self.assertEqual(
                    saved["stack_emit"]["9.6"], {"sha256": saved["sha256"], "version": 5, "transforms": []}
                )

    @unittest.skipIf(RULES_CONFIG.bypass_version_lock, "Version lock bypassed")
    def test_boundary_row_ignores_payload_changes_the_baseline_ignores(self):
        """related_integrations is in the emit payload but not in the baseline hash. A change there leaves the
        baseline clean at v6, so the boundary row, which mirrors the baseline, must stay at v6 unchanged rather
        than re-save a new hash under the shipped number."""
        import json
        import shutil
        import tempfile
        import tomllib
        from pathlib import Path
        from unittest import mock

        from detection_rules.config import load_current_package_version
        from detection_rules.rule_loader import RuleCollection
        from detection_rules.stack_emit import parse_stack
        from detection_rules.version_lock import VersionLock

        if parse_stack(load_current_package_version()) < parse_stack("9.6"):
            self.skipTest("models a 9.6 epoch distinct from 9.5; needs a 9.6+ package stack")

        rule_path = Path("rules/integrations/azure/privilege_escalation_azure_rbac_administrator_roles_assigned.toml")
        toml = tomllib.loads(rule_path.read_text())["rule"]
        with tempfile.TemporaryDirectory() as tmp:
            rule_copy = Path(tmp) / rule_path.name
            shutil.copy(rule_path, rule_copy)
            lock_path = Path(tmp) / "version.lock.json"
            dep_path = Path(tmp) / "deprecated_rules.json"
            dep_path.write_text("{}")
            baseline_hash = RuleCollection().load_file(rule_copy).contents.get_hash()
            entry = {
                "rule_name": toml["name"],
                "sha256": baseline_hash,
                "type": toml["type"],
                "version": 6,
                "stack_emit": {
                    "9.5": {"sha256": "1" * 64, "version": 4, "transforms": ["mitre_attack_v19"]},
                    "9.6": {"sha256": baseline_hash, "version": 6, "transforms": []},
                },
            }
            lock_path.write_text(json.dumps({toml["rule_id"]: entry}))
            lock = VersionLock(lock_path, dep_path, name="test")
            rc = RuleCollection()
            rc._version_lock = lock  # noqa: SLF001
            rule = rc.load_file(rule_copy)
            changed_payload = "9" * 64  # emit payload moved (e.g. related_integrations), still a no-op transform
            with (
                mock.patch("detection_rules.version_lock.emit_epoch_key", return_value="9.6"),
                mock.patch("detection_rules.rule.emit_epoch_key", return_value="9.6"),
                mock.patch("detection_rules.rule.loaded_version_lock", lock),
                mock.patch.object(type(rule.contents), "get_emit_hash", return_value=changed_payload),
                mock.patch.object(type(rule.contents), "get_untransformed_hash", return_value=changed_payload),
            ):
                self.assertFalse(rule.contents.is_dirty)
                self.assertFalse(rule.contents.is_emit_dirty)
                changed, _, _ = lock.manage_versions(rc, save_changes=True, verbose=False)
                self.assertNotIn(rule.id, changed)
                self.assertEqual(json.loads(lock_path.read_text())[toml["rule_id"]], entry)
                self.assertEqual(rule.contents.to_api_format()["version"], 6)

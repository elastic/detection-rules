# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Tests for stack emit epochs and version-lock channel resolution."""

import unittest
from typing import Any
from unittest import mock

from semver import Version

from detection_rules.stack_emit import (
    EmitContext,
    EmitTransform,
    apply_emit_transforms,
    emit_epoch_key,
    resolve_stack_emit_entry,
    rewrite_tactic_tags,
    transforms_for_stack,
)
from detection_rules.version_lock import VersionLockFile


class TestStackEmitHelpers(unittest.TestCase):
    """Unit tests for emit epoch helpers."""

    def test_epoch_shared_across_minors_without_new_transforms(self) -> None:
        """9.5 and 9.6 share the same epoch while only 9.5 transforms exist."""
        self.assertEqual(emit_epoch_key(Version(9, 5, 0)), "9.5")
        self.assertEqual(emit_epoch_key(Version(9, 6, 0)), "9.5")
        self.assertIsNone(emit_epoch_key(Version(9, 4, 0)))

    def test_transforms_empty_below_min_stack(self) -> None:
        """No transforms apply below 9.5."""
        self.assertEqual(transforms_for_stack(Version(9, 4, 0)), [])
        self.assertGreater(len(transforms_for_stack(Version(9, 5, 0))), 0)

    def test_resolve_inherits_highest_applicable_epoch(self) -> None:
        """Package 9.6 reuses the 9.5 emit entry when no 9.6 epoch exists."""
        stack_emit = {
            "9.5": {"sha256": "a" * 64, "version": 13, "transforms": ["mitre_attack_v19"]},
        }
        entry = resolve_stack_emit_entry(stack_emit, Version(9, 6, 0))
        assert entry is not None
        self.assertEqual(entry["version"], 13)
        self.assertIsNone(resolve_stack_emit_entry(stack_emit, Version(9, 4, 0)))

    def test_rewrite_tactic_tags_swaps_defense_evasion(self) -> None:
        """Obsolete baseline tactic tags are dropped; emitted tactic tags are added."""
        baseline = [
            {
                "tactic": {
                    "id": "TA0005",
                    "name": "Defense Evasion",
                    "reference": "https://attack.mitre.org/tactics/TA0005/",
                }
            }
        ]
        emitted = [
            {
                "tactic": {
                    "id": "TA0040",
                    "name": "Impact",
                    "reference": "https://attack.mitre.org/tactics/TA0040/",
                }
            }
        ]
        tags = ["Domain: Endpoint", "Tactic: Defense Evasion", "Data Source: foo"]
        rewritten = rewrite_tactic_tags(tags, baseline, emitted)
        self.assertIn("Domain: Endpoint", rewritten)
        self.assertIn("Data Source: foo", rewritten)
        self.assertNotIn("Tactic: Defense Evasion", rewritten)
        self.assertIn("Tactic: Impact", rewritten)

    def test_apply_emit_transforms_runs_registry_hooks(self) -> None:
        """apply_emit_transforms invokes each applicable transform's apply fn."""
        calls: list[str] = []

        def _mark(obj: dict[str, Any], stack: Version, context: EmitContext) -> None:
            _ = stack, context
            calls.append("ran")
            obj["marked"] = True

        synthetic = EmitTransform(
            id="test_marker",
            min_stack=Version(9, 9, 0),
            affects=("marked",),
            apply=_mark,
        )
        with mock.patch("detection_rules.stack_emit.EMIT_TRANSFORMS", (synthetic,)):
            obj: dict[str, Any] = {}
            apply_emit_transforms(obj, stack="9.8.0")
            self.assertEqual(calls, [])
            self.assertNotIn("marked", obj)

            apply_emit_transforms(obj, stack="9.9.0")
            self.assertEqual(calls, ["ran"])
            self.assertTrue(obj["marked"])


class TestVersionLockStackEmitSchema(unittest.TestCase):
    """Validate version.lock entries that include stack_emit."""

    def test_stack_emit_round_trip(self) -> None:
        """stack_emit is accepted and preserved on VersionLockFile entries."""
        contents: dict[str, Any] = {
            "33f306e8-417c-411b-965c-c2812d6d3f4d": {
                "rule_name": "Remote File Download via PowerShell",
                "sha256": "8679cd72bf85b67dde3dcfdaba749ed1fa6560bca5efd03ed41c76a500ce31d6",
                "type": "eql",
                "version": 4,
                "stack_emit": {
                    "9.5": {
                        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "version": 5,
                        "transforms": ["mitre_attack_v19", "related_integrations_gte"],
                    }
                },
            }
        }
        lock = VersionLockFile.from_dict({"data": contents})
        entry = lock["33f306e8-417c-411b-965c-c2812d6d3f4d"]
        self.assertIsNotNone(entry.stack_emit)
        self.assertEqual(entry.to_dict()["stack_emit"]["9.5"]["version"], 5)

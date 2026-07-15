# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Tests for multi-version threat mappings (e.g. MITRE ATT&CK v18/v19) support."""

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, ClassVar

from marshmallow import ValidationError

from detection_rules import attack
from detection_rules.config import (
    THREAT_MAPPING_VERSION_ENV,
)
from detection_rules.rule_loader import RuleCollection

TACTIC = {
    "id": "TA0001",
    "name": "Initial Access",
    "reference": "https://attack.mitre.org/tactics/TA0001/",
}
TECH_V18 = {"id": "T1078", "name": "Valid Accounts", "reference": "https://attack.mitre.org/techniques/T1078/"}
TECH_V19 = {"id": "T1078", "name": "Valid Accounts (v19)", "reference": "https://attack.mitre.org/techniques/T1078/"}


def _metadata() -> dict[str, Any]:
    """Return a minimal rule metadata dict for test fixtures."""
    return {
        "creation_date": "2020/12/15",
        "integration": ["endpoint"],
        "maturity": "production",
        "min_stack_comments": "test",
        "min_stack_version": "8.3.0",
        "updated_date": "2024/08/30",
    }


def _rule(threat_mappings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Return a minimal rule dict with a baseline v18 threat block."""
    rule: dict[str, Any] = {
        "author": ["Elastic"],
        "description": "Test rule.",
        "language": "eql",
        "name": "Threat Mapping Test Rule",
        "risk_score": 47,
        "rule_id": "5f7d1e2a-1111-2222-3333-444455556666",
        "severity": "low",
        "type": "eql",
        "query": "any where true",
        "threat": [{"framework": "MITRE ATT&CK", "tactic": TACTIC, "technique": [TECH_V18]}],
    }
    if threat_mappings is not None:
        rule["threat_mappings"] = threat_mappings
    return rule


def _v19_block(technique: dict[str, Any] = TECH_V19) -> dict[str, Any]:
    """Return a v19 threat_mappings block dict for use in test fixtures."""
    return {
        "framework": "MITRE ATT&CK",
        "version": "19",
        "threat": [{"framework": "MITRE ATT&CK", "tactic": TACTIC, "technique": [technique]}],
    }


class ThreatMappingEnv:
    """Context manager to temporarily set the output threat-mapping version env var."""

    def __init__(self, version: str | None) -> None:
        self.version = version
        self._prev: str | None = None

    def __enter__(self) -> None:
        self._prev = os.environ.get(THREAT_MAPPING_VERSION_ENV)
        if self.version is None:
            os.environ.pop(THREAT_MAPPING_VERSION_ENV, None)
        else:
            os.environ[THREAT_MAPPING_VERSION_ENV] = self.version

    def __exit__(self, *_: object) -> None:
        if self._prev is None:
            os.environ.pop(THREAT_MAPPING_VERSION_ENV, None)
        else:
            os.environ[THREAT_MAPPING_VERSION_ENV] = self._prev


class TestThreatHashStability(unittest.TestCase):
    """Hash stability: ID and structure changes trigger version bumps; ID changes must."""

    def _load(self, rule_dict: dict[str, Any]):
        """Load a rule dict into a RuleCollection."""
        return RuleCollection().load_dict({"metadata": _metadata(), "rule": rule_dict})

    def _hash(self, rule_dict: dict[str, Any]) -> str:
        """Compute the version-lock hash for a rule dict."""
        return self._load(rule_dict).contents.get_hash()

    def test_tactic_id_change_changes_hash(self) -> None:
        """Assert that changing a tactic ID produces a different hash."""
        tactic_a = {"id": "TA0005", "name": "Defense Evasion", "reference": "https://attack.mitre.org/tactics/TA0005/"}
        tactic_b = {"id": "TA0002", "name": "Execution", "reference": "https://attack.mitre.org/tactics/TA0002/"}
        tech = {"id": "T1036", "name": "Masquerading", "reference": "https://attack.mitre.org/techniques/T1036/"}
        rule_a = _rule()
        rule_a["threat"] = [{"framework": "MITRE ATT&CK", "tactic": tactic_a, "technique": [tech]}]
        rule_b = _rule()
        rule_b["threat"] = [{"framework": "MITRE ATT&CK", "tactic": tactic_b, "technique": [tech]}]
        self.assertNotEqual(self._hash(rule_a), self._hash(rule_b))

    def test_technique_id_change_changes_hash(self) -> None:
        """Assert that changing a technique ID produces a different hash."""
        tactic = {"id": "TA0005", "name": "Defense Evasion", "reference": "https://attack.mitre.org/tactics/TA0005/"}
        tech_a = {"id": "T1036", "name": "Masquerading", "reference": "https://attack.mitre.org/techniques/T1036/"}
        tech_b = {"id": "T1027", "name": "Obfuscated Files", "reference": "https://attack.mitre.org/techniques/T1027/"}
        rule_a = _rule()
        rule_a["threat"] = [{"framework": "MITRE ATT&CK", "tactic": tactic, "technique": [tech_a]}]
        rule_b = _rule()
        rule_b["threat"] = [{"framework": "MITRE ATT&CK", "tactic": tactic, "technique": [tech_b]}]
        self.assertNotEqual(self._hash(rule_a), self._hash(rule_b))

    def test_removing_technique_changes_hash(self) -> None:
        """Assert that removing a technique from a threat block produces a different hash."""
        tactic = {"id": "TA0005", "name": "Defense Evasion", "reference": "https://attack.mitre.org/tactics/TA0005/"}
        tech = {"id": "T1036", "name": "Masquerading", "reference": "https://attack.mitre.org/techniques/T1036/"}
        with_tech = _rule()
        with_tech["threat"] = [{"framework": "MITRE ATT&CK", "tactic": tactic, "technique": [tech]}]
        without_tech = _rule()
        without_tech["threat"] = [{"framework": "MITRE ATT&CK", "tactic": tactic}]
        self.assertNotEqual(self._hash(with_tech), self._hash(without_tech))


class TestVersionedThreatMappingSchema(unittest.TestCase):
    """Schema validation + build-time selection for `threat_mappings`."""

    def _load(self, rule_dict: dict[str, Any]):
        """Load a rule dict into a RuleCollection."""
        return RuleCollection().load_dict({"metadata": _metadata(), "rule": rule_dict})

    def test_loads_and_round_trips(self) -> None:
        """Assert that a rule with a v19 block loads and preserves the version field."""
        rule = self._load(_rule(threat_mappings=[_v19_block()]))
        self.assertEqual(len(rule.contents.data.threat_mappings), 1)
        self.assertEqual(rule.contents.data.threat_mappings[0].version, "19")

    def test_default_emits_baseline_and_strips_field(self) -> None:
        """Assert that v18 output emits the baseline threat and strips threat_mappings."""
        rule = self._load(_rule(threat_mappings=[_v19_block()]))
        with ThreatMappingEnv("18"):
            api = rule.contents.to_api_format()
        self.assertNotIn("threat_mappings", api)
        self.assertEqual(api["threat"][0]["technique"][0]["name"], "Valid Accounts")

    def test_selects_v19_when_configured(self) -> None:
        """Assert that v19 output emits the v19 threat block when configured."""
        rule = self._load(_rule(threat_mappings=[_v19_block()]))
        with ThreatMappingEnv("19"):
            api = rule.contents.to_api_format()
        self.assertNotIn("threat_mappings", api)
        self.assertEqual(api["threat"][0]["technique"][0]["name"], "Valid Accounts (v19)")

    def test_auto_converts_when_no_threat_mappings_block(self) -> None:
        """Assert that v19 output is auto-converted from baseline when no threat_mappings block exists."""
        rule = self._load(_rule())  # no threat_mappings — baseline only
        with ThreatMappingEnv("19"):
            api = rule.contents.to_api_format()
        self.assertNotIn("threat_mappings", api)
        tactic = api["threat"][0]["tactic"]
        # TA0001 (Initial Access) name is unchanged in v19
        self.assertEqual(tactic["id"], "TA0001")
        self.assertIn("name", tactic)

    def test_explicit_threat_mappings_overrides_auto_conversion(self) -> None:
        """Assert that an explicit threat_mappings block takes precedence over auto-conversion."""
        custom_tactic = {"id": "TA0001", "name": "Custom Name Override", "reference": "https://attack.mitre.org/tactics/TA0001/"}
        custom_tech = {"id": "T1078", "name": "Custom Tech Name", "reference": "https://attack.mitre.org/techniques/T1078/"}
        override_block = {
            "framework": "MITRE ATT&CK",
            "version": "19",
            "threat": [{"framework": "MITRE ATT&CK", "tactic": custom_tactic, "technique": [custom_tech]}],
        }
        rule = self._load(_rule(threat_mappings=[override_block]))
        with ThreatMappingEnv("19"):
            api = rule.contents.to_api_format()
        self.assertEqual(api["threat"][0]["tactic"]["name"], "Custom Name Override")
        self.assertEqual(api["threat"][0]["technique"][0]["name"], "Custom Tech Name")

    def test_missing_version_falls_back_to_default(self) -> None:
        """Assert that requesting an unconfigured version falls back to the baseline threat."""
        rule = self._load(_rule(threat_mappings=[_v19_block()]))
        with ThreatMappingEnv("20"):
            api = rule.contents.to_api_format()
        self.assertEqual(api["threat"][0]["technique"][0]["name"], "Valid Accounts")

    def test_duplicate_framework_version_rejected(self) -> None:
        """Assert that duplicate (framework, version) entries in threat_mappings are rejected."""
        with self.assertRaises(ValidationError):
            self._load(_rule(threat_mappings=[_v19_block(), _v19_block()]))

    def test_inner_framework_mismatch_rejected(self) -> None:
        """Assert that an inner threat framework disagreeing with the outer framework is rejected."""
        block = _v19_block()
        block["threat"][0]["framework"] = "MITRE ATLAS"
        with self.assertRaises(ValidationError):
            self._load(_rule(threat_mappings=[block]))

    def test_get_primary_tactic_names_baseline_only(self) -> None:
        """Assert that get_primary_tactic_names returns only the baseline tactic when no versioned blocks exist."""
        rule = self._load(_rule())
        self.assertEqual(rule.contents.data.get_primary_tactic_names(), ["Initial Access"])

    def test_get_primary_tactic_names_includes_versioned_blocks(self) -> None:
        """Assert that get_primary_tactic_names includes tactic names from versioned threat_mappings blocks."""
        v19_tactic = {
            "id": "TA0005",
            "name": "Stealth",
            "reference": "https://attack.mitre.org/tactics/TA0005/",
        }
        block = {
            "framework": "MITRE ATT&CK",
            "version": "19",
            "threat": [{"framework": "MITRE ATT&CK", "tactic": v19_tactic, "technique": [TECH_V19]}],
        }
        rule = self._load(_rule(threat_mappings=[block]))
        self.assertEqual(rule.contents.data.get_primary_tactic_names(), ["Initial Access", "Stealth"])


class TestAttackVersionMapLoader(unittest.TestCase):
    """Loading and lookups for the mapping config files."""

    MAP: ClassVar[dict[str, Any]] = {
        "framework": "MITRE ATT&CK",
        "source_version": "18",
        "target_version": "19",
        "tactics": {"TA0001": TACTIC},
        "techniques": {"T1078": TECH_V19, "T1100": None},
        "subtechniques": {},
    }

    def _write(self, directory: Path, name: str, data: dict[str, Any]) -> Path:
        """Write a YAML file to a directory and return its path."""
        import yaml

        path = directory / name
        path.write_text(yaml.safe_dump(data))
        return path

    def test_parse_and_lookup(self) -> None:
        """Assert that parse_attack_version_map parses a map file and supports key lookups."""
        with TemporaryDirectory() as tmp:
            path = self._write(Path(tmp), "m.yaml", self.MAP)
            vmap = attack.parse_attack_version_map(path)
            self.assertEqual(vmap.key, ("MITRE ATT&CK", "18", "19"))
            self.assertEqual(vmap.lookup("technique", "T1078"), TECH_V19)
            # explicit null and absent both resolve to None (dropped)
            self.assertIsNone(vmap.lookup("technique", "T1100"))
            self.assertIsNone(vmap.lookup("technique", "T9999"))
            self.assertTrue(vmap.is_mapped("technique", "T1078"))
            self.assertFalse(vmap.is_mapped("technique", "T1100"))

    def test_get_by_triple(self) -> None:
        """Assert that get_attack_version_map retrieves a map by (framework, source, target) and raises on missing."""
        with TemporaryDirectory() as tmp:
            self._write(Path(tmp), "m.yaml", self.MAP)
            vmap = attack.get_attack_version_map("MITRE ATT&CK", "18", "19", [Path(tmp)])
            self.assertEqual(vmap.target_version, "19")
            with self.assertRaises(ValueError):
                attack.get_attack_version_map("MITRE ATT&CK", "18", "99", [Path(tmp)])

    def test_missing_required_keys_rejected(self) -> None:
        """Assert that a map file missing required keys raises ValueError."""
        with TemporaryDirectory() as tmp:
            path = self._write(Path(tmp), "bad.yaml", {"framework": "MITRE ATT&CK"})
            with self.assertRaises(ValueError):
                attack.parse_attack_version_map(path)

    def test_malformed_destination_rejected(self) -> None:
        """Assert that a map file with a malformed destination entry raises ValueError."""
        bad = dict(self.MAP)
        bad["techniques"] = {"T1078": {"id": "T1078"}}  # missing name/reference
        with TemporaryDirectory() as tmp:
            path = self._write(Path(tmp), "bad.yaml", bad)
            with self.assertRaises(ValueError):
                attack.parse_attack_version_map(path)

    def test_duplicate_triple_rejected(self) -> None:
        """Assert that loading a directory with duplicate (framework, source, target) maps raises ValueError."""
        with TemporaryDirectory() as tmp:
            self._write(Path(tmp), "a.yaml", self.MAP)
            self._write(Path(tmp), "b.yaml", self.MAP)
            with self.assertRaises(ValueError):
                attack.load_attack_version_maps([Path(tmp)])

    def test_resolve_explicit_entry_wins(self) -> None:
        """Assert that resolve() returns the explicit config entry even when target_lookups is provided."""
        with TemporaryDirectory() as tmp:
            path = self._write(Path(tmp), "m.yaml", self.MAP)
            vmap = attack.parse_attack_version_map(path)
            lookups = attack.build_attack_lookups_for_version("19")
            # T1078 is in the explicit config → must return that, not STIX
            self.assertEqual(vmap.resolve("technique", "T1078", lookups), TECH_V19)
            # T1100 is explicitly null → must return None even with lookups present
            self.assertIsNone(vmap.resolve("technique", "T1100", lookups))

    def test_resolve_absent_without_auto_derive(self) -> None:
        """Assert that resolve() drops an absent id when auto_derive_missing is False."""
        with TemporaryDirectory() as tmp:
            path = self._write(Path(tmp), "m.yaml", self.MAP)
            vmap = attack.parse_attack_version_map(path)
            self.assertFalse(vmap.auto_derive_missing)
            lookups = attack.build_attack_lookups_for_version("19")
            self.assertIsNone(vmap.resolve("technique", "T9999", lookups))

    def test_resolve_absent_with_auto_derive(self) -> None:
        """Assert that resolve() auto-derives from STIX when auto_derive_missing is True and id exists in v19."""
        lean_map = {**self.MAP, "auto_derive_missing": True, "techniques": {}}
        with TemporaryDirectory() as tmp:
            path = self._write(Path(tmp), "lean.yaml", lean_map)
            vmap = attack.parse_attack_version_map(path)
            self.assertTrue(vmap.auto_derive_missing)
            lookups = attack.build_attack_lookups_for_version("19")
            # T1078 (Valid Accounts) exists in v19 and is not revoked
            result = vmap.resolve("technique", "T1078", lookups)
            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result["id"], "T1078")
            self.assertIn("name", result)
            self.assertTrue(result["reference"].endswith("/"))

    def test_resolve_tactic_auto_derive(self) -> None:
        """Assert that resolve() auto-derives tactic details from STIX when absent from config."""
        lean_map = {**self.MAP, "auto_derive_missing": True, "tactics": {}}
        with TemporaryDirectory() as tmp:
            path = self._write(Path(tmp), "lean.yaml", lean_map)
            vmap = attack.parse_attack_version_map(path)
            lookups = attack.build_attack_lookups_for_version("19")
            result = vmap.resolve("tactic", "TA0001", lookups)
            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result["id"], "TA0001")
            self.assertIn("name", result)
            self.assertIn("reference", result)


class TestRemapThreatEntry(unittest.TestCase):
    """Tactic-membership validation in _remap_threat_entry."""

    def _lean_vmap(self, tmp: Path) -> "attack.AttackVersionMap":
        """Return a lean auto_derive_missing vmap written to tmp."""
        import yaml

        data = {
            "framework": "MITRE ATT&CK",
            "source_version": "18",
            "target_version": "19",
            "auto_derive_missing": True,
        }
        path = tmp / "lean.yaml"
        path.write_text(yaml.safe_dump(data))
        return attack.parse_attack_version_map(path)

    def _entry(self, tactic_id: str, tactic_name: str, tech_id: str, tech_name: str) -> Any:
        """Return a ThreatMapping with a single technique under the given tactic."""
        from detection_rules.rule import ThreatMapping

        return ThreatMapping.from_dict(
            {
                "framework": "MITRE ATT&CK",
                "tactic": {
                    "id": tactic_id,
                    "name": tactic_name,
                    "reference": f"https://attack.mitre.org/tactics/{tactic_id}/",
                },
                "technique": [
                    {
                        "id": tech_id,
                        "name": tech_name,
                        "reference": f"https://attack.mitre.org/techniques/{tech_id}/",
                    }
                ],
            }
        )

    def test_technique_under_correct_tactic_passes(self) -> None:
        """Assert that a technique still under its source tactic in v19 is kept."""
        from detection_rules.devtools import _remap_threat_entry

        with TemporaryDirectory() as tmp:
            vmap = self._lean_vmap(Path(tmp))
            lookups = attack.build_attack_lookups_for_version("19")
            # T1078 (Valid Accounts) is under TA0001 (Initial Access) in both v18 and v19
            entry = self._entry("TA0001", "Initial Access", "T1078", "Valid Accounts")
            dropped: list[str] = []
            result = _remap_threat_entry(entry, vmap, "MITRE ATT&CK", dropped, lookups)
            self.assertIsNotNone(result)
            self.assertEqual(dropped, [])

    def test_technique_moved_to_new_tactic_is_dropped(self) -> None:
        """Assert that a technique no longer under its source tactic in v19 is dropped with an explanation."""
        from detection_rules.devtools import _remap_threat_entry

        with TemporaryDirectory() as tmp:
            vmap = self._lean_vmap(Path(tmp))
            lookups = attack.build_attack_lookups_for_version("19")
            # T1112 (Modify Registry) was under TA0005 in v18 but moved to TA0112 in v19
            entry = self._entry("TA0005", "Defense Evasion", "T1112", "Modify Registry")
            dropped: list[str] = []
            result = _remap_threat_entry(entry, vmap, "MITRE ATT&CK", dropped, lookups)
            self.assertIsNotNone(result)  # tactic entry still emitted (may have other techniques)
            self.assertEqual(len(dropped), 1)
            self.assertIn("T1112", dropped[0])
            self.assertIn("TA0112", dropped[0])

    def test_no_target_lookups_skips_validation(self) -> None:
        """Assert that tactic-membership validation is skipped when target_lookups is None."""
        from detection_rules.devtools import _remap_threat_entry

        with TemporaryDirectory() as tmp:
            # Explicit config map with T1112 mapped to itself (no auto_derive_missing)
            import yaml

            data = {
                "framework": "MITRE ATT&CK",
                "source_version": "18",
                "target_version": "19",
                "tactics": {
                    "TA0005": {
                        "id": "TA0005",
                        "name": "Stealth",
                        "reference": "https://attack.mitre.org/tactics/TA0005/",
                    }
                },
                "techniques": {
                    "T1112": {
                        "id": "T1112",
                        "name": "Modify Registry",
                        "reference": "https://attack.mitre.org/techniques/T1112/",
                    }
                },
                "subtechniques": {},
            }
            path = Path(tmp) / "explicit.yaml"
            path.write_text(yaml.safe_dump(data))
            vmap = attack.parse_attack_version_map(path)
            entry = self._entry("TA0005", "Defense Evasion", "T1112", "Modify Registry")
            dropped: list[str] = []
            result = _remap_threat_entry(entry, vmap, "MITRE ATT&CK", dropped, target_lookups=None)
            self.assertIsNotNone(result)
            self.assertEqual(dropped, [])  # no validation without target_lookups


class TestIdentityScaffold(unittest.TestCase):
    """Tests for build_identity_version_map scaffold generation."""

    def test_build_identity_version_map(self) -> None:
        """Assert that build_identity_version_map produces a valid identity skeleton."""
        skeleton = attack.build_identity_version_map("MITRE ATT&CK", "18", "19")
        self.assertEqual(skeleton["source_version"], "18")
        self.assertEqual(skeleton["target_version"], "19")
        self.assertGreater(len(skeleton["techniques"]), 0)
        # identity entries map an id to itself with a name/reference
        sample_id, sample = next(iter(skeleton["techniques"].items()))
        self.assertEqual(sample_id, sample["id"])
        self.assertIn("reference", sample)
        # revoked/deprecated ids are excluded from the identity baseline
        for revoked_id in attack.revoked:
            self.assertNotIn(revoked_id, skeleton["techniques"])
            self.assertNotIn(revoked_id, skeleton["subtechniques"])

    def test_scaffold_uses_v18_source_keys(self) -> None:
        """Source keys must come from v18; new v19-only IDs must not appear as source keys."""
        skeleton = attack.build_identity_version_map("MITRE ATT&CK", "18", "19")
        v18_lookups = attack.build_attack_lookups_for_version("18")
        v19_lookups = attack.build_attack_lookups_for_version("19")
        # TA0112 is new in v19; it must not appear as a source key in a v18->v19 map
        v19_only_tactics = set(v19_lookups.tactics_map.values()) - set(v18_lookups.tactics_map.values())
        for tactic_id in v19_only_tactics:
            self.assertNotIn(tactic_id, skeleton["tactics"])

    def test_scaffold_uses_v19_tactic_names(self) -> None:
        """Tactic names in the scaffold must come from v19, not v18."""
        skeleton = attack.build_identity_version_map("MITRE ATT&CK", "18", "19")
        v19_lookups = attack.build_attack_lookups_for_version("19")
        v19_tactic_id_to_name = {v: k for k, v in v19_lookups.tactics_map.items()}
        for tactic_id, entry in skeleton["tactics"].items():
            if tactic_id in v19_tactic_id_to_name:
                self.assertEqual(
                    entry["name"],
                    v19_tactic_id_to_name[tactic_id],
                    f"Scaffold tactic {tactic_id} has v18 name '{entry['name']}' "
                    f"instead of v19 name '{v19_tactic_id_to_name[tactic_id]}'",
                )

    def test_scaffold_uses_v19_technique_names(self) -> None:
        """Technique names that exist in v19 must reflect the v19 name."""
        skeleton = attack.build_identity_version_map("MITRE ATT&CK", "18", "19")
        v19_lookups = attack.build_attack_lookups_for_version("19")
        for technique_id, entry in skeleton["techniques"].items():
            if technique_id in v19_lookups.technique_lookup:
                expected = v19_lookups.technique_lookup[technique_id]["name"]
                self.assertEqual(
                    entry["name"],
                    expected,
                    f"Scaffold technique {technique_id} has name '{entry['name']}' instead of v19 name '{expected}'",
                )


if __name__ == "__main__":
    unittest.main()

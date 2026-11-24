# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Tests for multi-version threat mappings (baseline and promoted MITRE ATT&CK versions)."""

import contextlib
import importlib.util
import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, ClassVar
from unittest import mock

from marshmallow import ValidationError

from detection_rules import attack
from detection_rules.config import (
    DEFAULT_THREAT_MAPPING_VERSION,
    PROMOTED_THREAT_MAPPING_VERSION,
    THREAT_MAPPING_VERSION_ENV,
)
from detection_rules.rule_loader import RuleCollection
from detection_rules.schemas import get_stack_schemas
from detection_rules.stack_emit import PROMOTED_THREAT_MAPPING_MIN_STACK
from detection_rules.utils import get_etc_path

# Versions under test come from config, so an ATT&CK upgrade does not need edits here.
BASELINE = DEFAULT_THREAT_MAPPING_VERSION
PROMOTED = PROMOTED_THREAT_MAPPING_VERSION

TACTIC = {
    "id": "TA0001",
    "name": "Initial Access",
    "reference": "https://attack.mitre.org/tactics/TA0001/",
}
TECH_BASELINE = {"id": "T1078", "name": "Valid Accounts", "reference": "https://attack.mitre.org/techniques/T1078/"}
TECH_PROMOTED = {
    "id": "T1078",
    "name": "Valid Accounts (promoted)",
    "reference": "https://attack.mitre.org/techniques/T1078/",
}


class TestAttackVersionInitialization(unittest.TestCase):
    """Tests for deriving the baseline ATT&CK version during module initialization."""

    def test_parent_path_with_version_delimiter(self) -> None:
        """A parent directory containing `-v` must not affect ATT&CK filename parsing."""
        attack_path = Path("test-v01/installed/detection_rules/etc/attack-v18.1.0.json.gz")
        module_name = "detection_rules._attack_regression_test"
        spec = importlib.util.spec_from_file_location(module_name, attack.__file__)
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)

        with (
            mock.patch("detection_rules.utils.get_etc_glob_path", return_value=[attack_path]),
            mock.patch("detection_rules.utils.read_gzip", return_value='{"objects": []}'),
            mock.patch.dict(sys.modules, {module_name: module}),
        ):
            spec.loader.exec_module(module)

        self.assertEqual(module.CURRENT_ATTACK_VERSION, "18.1.0")


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
    """Return a minimal rule dict with a baseline threat block."""
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
        "threat": [{"framework": "MITRE ATT&CK", "tactic": TACTIC, "technique": [TECH_BASELINE]}],
    }
    if threat_mappings is not None:
        rule["threat_mappings"] = threat_mappings
    return rule


@contextlib.contextmanager
def _pin_promoted_stack() -> Any:
    """Pin the emit stack to the promotion gate so stack-gated transforms apply on release branches (< 9.5)."""
    # `load_current_package_version` is imported by name into both the rule module and the schemas
    # module. Pinning only the rule module makes `get_required_fields` ask `get_stack_schemas()` for a
    # version the schemas module (still reading the real package) never lists on a < 9.5 branch. Pin
    # both, and drop the memoized `get_stack_schemas` result so it is rebuilt for the pinned version.
    pinned = str(PROMOTED_THREAT_MAPPING_MIN_STACK)
    get_stack_schemas.clear()
    try:
        with (
            mock.patch("detection_rules.rule.load_current_package_version", return_value=pinned),
            mock.patch("detection_rules.schemas.load_current_package_version", return_value=pinned),
        ):
            yield
    finally:
        get_stack_schemas.clear()


def _promoted_block(technique: dict[str, Any] = TECH_PROMOTED) -> dict[str, Any]:
    """Return a promoted-version threat_mappings block dict for use in test fixtures."""
    return {
        "framework": "MITRE ATT&CK",
        "version": PROMOTED,
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
        """Assert that changing a tactic ID produces a different hash (baseline context)."""
        tactic_a = {"id": "TA0005", "name": "Defense Evasion", "reference": "https://attack.mitre.org/tactics/TA0005/"}
        tactic_b = {"id": "TA0002", "name": "Execution", "reference": "https://attack.mitre.org/tactics/TA0002/"}
        tech = {"id": "T1036", "name": "Masquerading", "reference": "https://attack.mitre.org/techniques/T1036/"}
        rule_a = _rule()
        rule_a["threat"] = [{"framework": "MITRE ATT&CK", "tactic": tactic_a, "technique": [tech]}]
        rule_b = _rule()
        rule_b["threat"] = [{"framework": "MITRE ATT&CK", "tactic": tactic_b, "technique": [tech]}]
        with ThreatMappingEnv(BASELINE):
            self.assertNotEqual(self._hash(rule_a), self._hash(rule_b))

    def test_technique_id_change_changes_hash(self) -> None:
        """Assert that changing a technique ID produces a different hash (baseline context)."""
        tactic = {"id": "TA0005", "name": "Defense Evasion", "reference": "https://attack.mitre.org/tactics/TA0005/"}
        tech_a = {"id": "T1036", "name": "Masquerading", "reference": "https://attack.mitre.org/techniques/T1036/"}
        tech_b = {"id": "T1027", "name": "Obfuscated Files", "reference": "https://attack.mitre.org/techniques/T1027/"}
        rule_a = _rule()
        rule_a["threat"] = [{"framework": "MITRE ATT&CK", "tactic": tactic, "technique": [tech_a]}]
        rule_b = _rule()
        rule_b["threat"] = [{"framework": "MITRE ATT&CK", "tactic": tactic, "technique": [tech_b]}]
        with ThreatMappingEnv(BASELINE):
            self.assertNotEqual(self._hash(rule_a), self._hash(rule_b))

    def test_removing_technique_changes_hash(self) -> None:
        """Assert that removing a technique from a threat block produces a different hash (baseline context)."""
        tactic = {"id": "TA0005", "name": "Defense Evasion", "reference": "https://attack.mitre.org/tactics/TA0005/"}
        tech = {"id": "T1036", "name": "Masquerading", "reference": "https://attack.mitre.org/techniques/T1036/"}
        with_tech = _rule()
        with_tech["threat"] = [{"framework": "MITRE ATT&CK", "tactic": tactic, "technique": [tech]}]
        without_tech = _rule()
        without_tech["threat"] = [{"framework": "MITRE ATT&CK", "tactic": tactic}]
        with ThreatMappingEnv(BASELINE):
            self.assertNotEqual(self._hash(with_tech), self._hash(without_tech))


class TestVersionedThreatMappingSchema(unittest.TestCase):
    """Schema validation + build-time selection for `threat_mappings`."""

    def _load(self, rule_dict: dict[str, Any]):
        """Load a rule dict into a RuleCollection."""
        return RuleCollection().load_dict({"metadata": _metadata(), "rule": rule_dict})

    def test_loads_and_round_trips(self) -> None:
        """Assert that a rule with a promoted-version block loads and preserves the version field."""
        rule = self._load(_rule(threat_mappings=[_promoted_block()]))
        self.assertEqual(len(rule.contents.data.threat_mappings), 1)
        self.assertEqual(rule.contents.data.threat_mappings[0].version, PROMOTED)

    def test_default_emits_baseline_and_strips_field(self) -> None:
        """Assert that baseline output emits the baseline threat and strips threat_mappings."""
        rule = self._load(_rule(threat_mappings=[_promoted_block()]))
        with ThreatMappingEnv(BASELINE):
            api = rule.contents.to_api_format()
        self.assertNotIn("threat_mappings", api)
        self.assertEqual(api["threat"][0]["technique"][0]["name"], "Valid Accounts")

    def test_selects_promoted_when_configured(self) -> None:
        """Assert that promoted output emits the promoted threat block when configured."""
        rule = self._load(_rule(threat_mappings=[_promoted_block()]))
        with ThreatMappingEnv(PROMOTED), _pin_promoted_stack():
            api = rule.contents.to_api_format()
        self.assertNotIn("threat_mappings", api)
        self.assertEqual(api["threat"][0]["technique"][0]["name"], "Valid Accounts (promoted)")

    def test_falls_back_to_baseline_when_no_threat_mappings_block(self) -> None:
        """Assert that an unknown target version without a map falls back to the baseline threat."""
        rule = self._load(_rule())  # no threat_mappings — baseline only
        with ThreatMappingEnv("99"):
            api = rule.contents.to_api_format()
        self.assertNotIn("threat_mappings", api)
        # No baseline->v99 map: baseline threat should be emitted unchanged
        tactic = api["threat"][0]["tactic"]
        self.assertEqual(tactic["id"], TACTIC["id"])
        self.assertEqual(tactic["name"], TACTIC["name"])
        tech = api["threat"][0]["technique"][0]
        self.assertEqual(tech["id"], TECH_BASELINE["id"])

    def test_auto_converts_when_no_threat_mappings_block(self) -> None:
        """Assert that promoted output auto-converts from baseline when no threat_mappings exist."""
        rule = self._load(_rule())
        with ThreatMappingEnv(PROMOTED), _pin_promoted_stack():
            api = rule.contents.to_api_format(apply_emit_transforms=True)
        self.assertNotIn("threat_mappings", api)
        self.assertTrue(api.get("threat"))
        # T1078 still exists in the promoted version under Initial Access
        tech_ids = {t["id"] for entry in api["threat"] for t in entry.get("technique") or []}
        self.assertIn("T1078", tech_ids)

    def test_baseline_hash_ignores_emit_transforms(self) -> None:
        """Assert baseline get_hash is identical whether or not emit would transform threat."""
        rule = self._load(_rule())
        with ThreatMappingEnv(BASELINE):
            hash_baseline = rule.contents.get_hash()
        with ThreatMappingEnv(PROMOTED):
            hash_promoted_context = rule.contents.get_hash()
            emit_hash = rule.contents.get_emit_hash()
        self.assertEqual(hash_baseline, hash_promoted_context)
        self.assertNotEqual(hash_baseline, emit_hash)

    def test_explicit_threat_mappings_overrides_auto_conversion(self) -> None:
        """Assert that an explicit threat_mappings block takes precedence over auto-conversion."""
        custom_tactic = {
            "id": "TA0001",
            "name": "Custom Name Override",
            "reference": "https://attack.mitre.org/tactics/TA0001/",
        }
        custom_tech = {
            "id": "T1078",
            "name": "Custom Tech Name",
            "reference": "https://attack.mitre.org/techniques/T1078/",
        }
        override_block = {
            "framework": "MITRE ATT&CK",
            "version": PROMOTED,
            "threat": [{"framework": "MITRE ATT&CK", "tactic": custom_tactic, "technique": [custom_tech]}],
        }
        rule = self._load(_rule(threat_mappings=[override_block]))
        with ThreatMappingEnv(PROMOTED), _pin_promoted_stack():
            api = rule.contents.to_api_format()
        self.assertEqual(api["threat"][0]["tactic"]["name"], "Custom Name Override")
        self.assertEqual(api["threat"][0]["technique"][0]["name"], "Custom Tech Name")

    def test_missing_version_falls_back_to_default(self) -> None:
        """Assert that requesting an unconfigured version falls back to the baseline threat."""
        rule = self._load(_rule(threat_mappings=[_promoted_block()]))
        with ThreatMappingEnv("99"):
            api = rule.contents.to_api_format()
        self.assertEqual(api["threat"][0]["technique"][0]["name"], "Valid Accounts")

    def test_duplicate_framework_version_rejected(self) -> None:
        """Assert that duplicate (framework, version) entries in threat_mappings are rejected."""
        with self.assertRaises(ValidationError):
            self._load(_rule(threat_mappings=[_promoted_block(), _promoted_block()]))

    def test_inner_framework_mismatch_rejected(self) -> None:
        """Assert that an inner threat framework disagreeing with the outer framework is rejected."""
        block = _promoted_block()
        block["threat"][0]["framework"] = "MITRE ATLAS"
        with self.assertRaises(ValidationError):
            self._load(_rule(threat_mappings=[block]))

    def test_get_primary_tactic_names_baseline_only(self) -> None:
        """Assert that get_primary_tactic_names returns only the baseline tactic when no versioned blocks exist."""
        rule = self._load(_rule())
        self.assertEqual(rule.contents.data.get_primary_tactic_names(), ["Initial Access"])

    def test_get_primary_tactic_names_includes_versioned_blocks(self) -> None:
        """Assert that get_primary_tactic_names includes tactic names from versioned threat_mappings blocks."""
        promoted_tactic = {
            "id": "TA0005",
            "name": "Stealth",
            "reference": "https://attack.mitre.org/tactics/TA0005/",
        }
        block = {
            "framework": "MITRE ATT&CK",
            "version": PROMOTED,
            "threat": [{"framework": "MITRE ATT&CK", "tactic": promoted_tactic, "technique": [TECH_PROMOTED]}],
        }
        rule = self._load(_rule(threat_mappings=[block]))
        self.assertEqual(rule.contents.data.get_primary_tactic_names(), ["Initial Access", "Stealth"])


class TestAttackVersionMapLoader(unittest.TestCase):
    """Loading and lookups for the mapping config files."""

    MAP: ClassVar[dict[str, Any]] = {
        "framework": "MITRE ATT&CK",
        "source_version": BASELINE,
        "target_version": PROMOTED,
        "tactics": {"TA0001": TACTIC},
        "techniques": {"T1078": TECH_PROMOTED, "T1100": None},
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
            self.assertEqual(vmap.key, ("MITRE ATT&CK", BASELINE, PROMOTED))
            self.assertEqual(vmap.lookup("technique", "T1078"), TECH_PROMOTED)
            # explicit null and absent both resolve to None (dropped)
            self.assertIsNone(vmap.lookup("technique", "T1100"))
            self.assertIsNone(vmap.lookup("technique", "T9999"))
            self.assertTrue(vmap.is_mapped("technique", "T1078"))
            self.assertFalse(vmap.is_mapped("technique", "T1100"))

    def test_get_by_triple(self) -> None:
        """Assert that get_attack_version_map retrieves a map by (framework, source, target) and raises on missing."""
        with TemporaryDirectory() as tmp:
            self._write(Path(tmp), "m.yaml", self.MAP)
            vmap = attack.get_attack_version_map("MITRE ATT&CK", BASELINE, PROMOTED, [Path(tmp)])
            self.assertEqual(vmap.target_version, PROMOTED)
            with self.assertRaises(ValueError):
                attack.get_attack_version_map("MITRE ATT&CK", BASELINE, "99", [Path(tmp)])

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
            lookups = attack.build_attack_lookups_for_version(PROMOTED)
            # T1078 is in the explicit config → must return that, not STIX
            self.assertEqual(vmap.resolve("technique", "T1078", lookups), TECH_PROMOTED)
            # T1100 is explicitly null → must return None even with lookups present
            self.assertIsNone(vmap.resolve("technique", "T1100", lookups))

    def test_resolve_absent_without_auto_derive(self) -> None:
        """Assert that resolve() drops an absent id when auto_derive_missing is False."""
        with TemporaryDirectory() as tmp:
            path = self._write(Path(tmp), "m.yaml", self.MAP)
            vmap = attack.parse_attack_version_map(path)
            self.assertFalse(vmap.auto_derive_missing)
            lookups = attack.build_attack_lookups_for_version(PROMOTED)
            self.assertIsNone(vmap.resolve("technique", "T9999", lookups))

    def test_resolve_absent_with_auto_derive(self) -> None:
        """Assert that resolve() auto-derives from STIX when auto_derive_missing is True and id exists in the target."""
        lean_map = {**self.MAP, "auto_derive_missing": True, "techniques": {}}
        with TemporaryDirectory() as tmp:
            path = self._write(Path(tmp), "lean.yaml", lean_map)
            vmap = attack.parse_attack_version_map(path)
            self.assertTrue(vmap.auto_derive_missing)
            lookups = attack.build_attack_lookups_for_version(PROMOTED)
            # T1078 (Valid Accounts) exists in the promoted version and is not revoked
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
            lookups = attack.build_attack_lookups_for_version(PROMOTED)
            result = vmap.resolve("tactic", "TA0001", lookups)
            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result["id"], "TA0001")
            self.assertIn("name", result)
            self.assertIn("reference", result)


class TestShippedVersionMap(unittest.TestCase):
    """The shipped baseline -> promoted map stays consistent with the ATT&CK STIX data it converts between."""

    @classmethod
    def setUpClass(cls) -> None:
        maps_dir = get_etc_path([attack.ATTACK_VERSION_MAPS_DIRNAME])
        cls.vmap = attack.get_attack_version_map("MITRE ATT&CK", BASELINE, PROMOTED, [maps_dir])
        cls.source = attack.build_attack_lookups_for_version(BASELINE)
        cls.target = attack.build_attack_lookups_for_version(PROMOTED)

    def test_explicit_destinations_are_active_in_target(self) -> None:
        """Every explicit destination is a live promoted-version id carrying that version's name."""
        for table in (self.vmap.techniques, self.vmap.subtechniques):
            for source_id, dest in table.items():
                if dest is None:
                    continue
                item = self.target.technique_lookup.get(dest["id"])
                self.assertIsNotNone(item, f"{source_id} maps to {dest['id']}, which is not in v{PROMOTED}")
                assert item is not None
                self.assertFalse(item.get("revoked"), f"{source_id} maps to revoked id {dest['id']}")
                self.assertFalse(item.get("x_mitre_deprecated"), f"{source_id} maps to deprecated id {dest['id']}")
                self.assertEqual(dest["name"], item["name"], f"{source_id} -> {dest['id']} name is stale")

    def test_ids_revoked_in_target_have_explicit_entries(self) -> None:
        """Ids active in the baseline but revoked in the promoted version need an explicit entry.

        Auto-derive would otherwise drop them.
        """
        for source_id in self.source.technique_lookup:
            if source_id in self.source.revoked or source_id in self.source.deprecated:
                continue
            if source_id not in self.target.revoked:
                continue
            table = self.vmap.subtechniques if "." in source_id else self.vmap.techniques
            self.assertIn(
                source_id, table, f"{source_id} is revoked in v{PROMOTED} but has no entry in {self.vmap.path.name}"
            )


class TestRemapThreatEntries(unittest.TestCase):
    """Tactic-membership validation and cross-entry grouping in _remap_threat_entries."""

    def _lean_vmap(self, tmp: Path) -> "attack.AttackVersionMap":
        """Return a lean auto_derive_missing vmap written to tmp."""
        import yaml

        data = {
            "framework": "MITRE ATT&CK",
            "source_version": BASELINE,
            "target_version": PROMOTED,
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
        """Assert that a technique still under its source tactic in the promoted version is kept."""
        from detection_rules.devtools import _remap_threat_entries

        with TemporaryDirectory() as tmp:
            vmap = self._lean_vmap(Path(tmp))
            lookups = attack.build_attack_lookups_for_version(PROMOTED)
            # T1078 (Valid Accounts) is under TA0001 (Initial Access) in both versions
            entry = self._entry("TA0001", "Initial Access", "T1078", "Valid Accounts")
            dropped: list[str] = []
            result = _remap_threat_entries([entry], vmap, "MITRE ATT&CK", dropped, lookups)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["tactic"]["id"], "TA0001")
            self.assertEqual(dropped, [])

    def test_technique_moved_to_new_tactic_follows_migration(self) -> None:
        """Assert that a technique that migrated to a new tactic is emitted under that tactic."""
        from detection_rules.devtools import _remap_threat_entries

        with TemporaryDirectory() as tmp:
            vmap = self._lean_vmap(Path(tmp))
            lookups = attack.build_attack_lookups_for_version(PROMOTED)
            # T1112 (Modify Registry) is under TA0005 in the baseline and moved to TA0112 in ATT&CK v19
            entry = self._entry("TA0005", "Defense Evasion", "T1112", "Modify Registry")
            dropped: list[str] = []
            moved: list[str] = []
            result = _remap_threat_entries([entry], vmap, "MITRE ATT&CK", dropped, lookups, moved)
            self.assertEqual(dropped, [])  # not dropped — followed its migration
            self.assertEqual(len(moved), 1)
            self.assertIn("T1112", moved[0])
            self.assertIn("TA0112", moved[0])
            # Result should contain TA0112 entry with T1112, not the original TA0005
            tactic_ids = [e["tactic"]["id"] for e in result]
            self.assertIn("TA0112", tactic_ids)
            self.assertNotIn("TA0005", tactic_ids)
            ta0112_entry = next(e for e in result if e["tactic"]["id"] == "TA0112")
            tech_ids = [t["id"] for t in ta0112_entry.get("technique", [])]
            self.assertIn("T1112", tech_ids)

    def test_cross_entry_migration_merges_into_single_tactic_entry(self) -> None:
        """Assert that a technique migrating into a tactic another source entry maps to does not duplicate it."""
        from detection_rules.devtools import _remap_threat_entries

        with TemporaryDirectory() as tmp:
            vmap = self._lean_vmap(Path(tmp))
            lookups = attack.build_attack_lookups_for_version(PROMOTED)
            # T1543 stays under TA0003 (Persistence); T1112 migrates from TA0005 (Defense
            # Evasion) into TA0112 AND TA0003 — it must merge into the existing TA0003 entry.
            entries = [
                self._entry("TA0003", "Persistence", "T1543", "Create or Modify System Process"),
                self._entry("TA0005", "Defense Evasion", "T1112", "Modify Registry"),
            ]
            dropped: list[str] = []
            result = _remap_threat_entries(entries, vmap, "MITRE ATT&CK", dropped, lookups)
            self.assertEqual(dropped, [])
            tactic_ids = [e["tactic"]["id"] for e in result]
            self.assertEqual(len(tactic_ids), len(set(tactic_ids)), f"duplicate tactic entries: {tactic_ids}")
            self.assertIn("TA0003", tactic_ids)
            self.assertIn("TA0112", tactic_ids)
            self.assertNotIn("TA0005", tactic_ids)
            ta0003_entry = next(e for e in result if e["tactic"]["id"] == "TA0003")
            tech_ids = sorted(t["id"] for t in ta0003_entry.get("technique", []))
            self.assertEqual(tech_ids, ["T1112", "T1543"])

    def test_no_target_lookups_skips_validation(self) -> None:
        """Assert that tactic-membership validation is skipped when target_lookups is None."""
        from detection_rules.devtools import _remap_threat_entries

        with TemporaryDirectory() as tmp:
            # Explicit config map with T1112 mapped to itself (no auto_derive_missing)
            import yaml

            data = {
                "framework": "MITRE ATT&CK",
                "source_version": BASELINE,
                "target_version": PROMOTED,
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
            result = _remap_threat_entries([entry], vmap, "MITRE ATT&CK", dropped, target_lookups=None)
            self.assertEqual(len(result), 1)
            self.assertEqual(dropped, [])  # no validation without target_lookups


class TestOutputVersionResolution(unittest.TestCase):
    """Auto-promotion behavior in resolve_output_threat_version."""

    def _resolve_with(self, pinned: bool) -> tuple[str, str]:
        """Resolve the output version against a mocked 9.5 stack with the given config pin state."""
        import dataclasses
        from unittest import mock

        from detection_rules.config import parse_rules_config

        cfg = dataclasses.replace(
            parse_rules_config(),
            threat_mapping_version=BASELINE,
            threat_mapping_version_pinned=pinned,
        )
        with (
            ThreatMappingEnv(None),
            mock.patch("detection_rules.attack.parse_rules_config", return_value=cfg),
            mock.patch("detection_rules.attack.load_current_package_version", return_value="9.5.0"),
        ):
            return attack.resolve_output_threat_version()

    def test_auto_promotes_on_9_5_when_unpinned(self) -> None:
        """Assert that stack >= 9.5 auto-promotes when no version is pinned."""
        _, version = self._resolve_with(pinned=False)
        self.assertEqual(version, PROMOTED)

    def test_config_pin_suppresses_auto_promotion(self) -> None:
        """Assert that an explicit config-pinned version suppresses auto-promotion."""
        _, version = self._resolve_with(pinned=True)
        self.assertEqual(version, BASELINE)


class TestPatchTomlMinimal(unittest.TestCase):
    """Surgical TOML patch helpers used by convert-threat-mappings."""

    def test_insert_tags_multiline(self) -> None:
        """Assert that tags are inserted into a multi-line array with comma repair."""
        from detection_rules.devtools import _insert_tags

        text = 'tags = [\n    "A",\n    "B"\n]\n'
        out, warning = _insert_tags(text, ["C"])
        self.assertIsNone(warning)
        self.assertEqual(out, 'tags = [\n    "A",\n    "B",\n    "C",\n]\n')

    def test_insert_tags_single_line(self) -> None:
        """Assert that tags are inserted into a single-line array in place."""
        from detection_rules.devtools import _insert_tags

        text = 'tags = ["A", "B"]\n'
        out, warning = _insert_tags(text, ["C"])
        self.assertIsNone(warning)
        self.assertEqual(out, 'tags = ["A", "B", "C"]\n')

    def test_insert_tags_missing_array_warns(self) -> None:
        """Assert that a missing tags array produces a warning instead of a silent no-op."""
        from detection_rules.devtools import _insert_tags

        text = 'name = "x"\n'
        out, warning = _insert_tags(text, ["C"])
        self.assertEqual(out, text)
        self.assertIsNotNone(warning)
        assert warning is not None
        self.assertIn("tags array not found", warning)

    def test_toml_str_escapes_quotes_and_backslashes(self) -> None:
        """Assert that TOML string serialization escapes quotes and backslashes."""
        from detection_rules.devtools import _toml_str

        self.assertEqual(_toml_str('a"b\\c'), '"a\\"b\\\\c"')
        self.assertEqual(_toml_str("plain"), '"plain"')

    def test_patch_refuses_when_section_follows_threat_mappings(self) -> None:
        """Assert that a file with content after [[rule.threat_mappings]] is left unmodified."""
        from detection_rules.devtools import _patch_toml_minimal

        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "rule.toml"
            _ = path.write_text(
                '[metadata]\nupdated_date = "2020/01/01"\n\n[rule]\nname = "x"\n\n'
                '[[rule.threat_mappings]]\nframework = "MITRE ATT&CK"\nversion = "1"\n\n'
                "[rule.other]\nvalue = 1\n"
            )
            original = path.read_text()
            applied, warnings = _patch_toml_minimal(path, "2026/07/16", [], [])
            self.assertFalse(applied)
            self.assertTrue(warnings)
            self.assertIn("rule.other", warnings[0])
            self.assertEqual(path.read_text(), original)


class TestIdentityScaffold(unittest.TestCase):
    """Tests for build_identity_version_map scaffold generation."""

    def test_build_identity_version_map(self) -> None:
        """Assert that build_identity_version_map produces a valid identity skeleton."""
        skeleton = attack.build_identity_version_map("MITRE ATT&CK", BASELINE, PROMOTED)
        self.assertEqual(skeleton["source_version"], BASELINE)
        self.assertEqual(skeleton["target_version"], PROMOTED)
        self.assertGreater(len(skeleton["techniques"]), 0)
        # identity entries map an id to itself with a name/reference
        sample_id, sample = next(iter(skeleton["techniques"].items()))
        self.assertEqual(sample_id, sample["id"])
        self.assertIn("reference", sample)
        # revoked/deprecated ids are excluded from the identity baseline
        for revoked_id in attack.revoked:
            self.assertNotIn(revoked_id, skeleton["techniques"])
            self.assertNotIn(revoked_id, skeleton["subtechniques"])

    def test_scaffold_uses_baseline_source_keys(self) -> None:
        """Source keys must come from the baseline; promoted-only IDs must not appear as source keys."""
        skeleton = attack.build_identity_version_map("MITRE ATT&CK", BASELINE, PROMOTED)
        baseline_lookups = attack.build_attack_lookups_for_version(BASELINE)
        promoted_lookups = attack.build_attack_lookups_for_version(PROMOTED)
        # e.g. TA0112 was added in ATT&CK v19; it must not appear as a source key in a baseline map
        promoted_only_tactics = set(promoted_lookups.tactics_map.values()) - set(baseline_lookups.tactics_map.values())
        for tactic_id in promoted_only_tactics:
            self.assertNotIn(tactic_id, skeleton["tactics"])

    def test_scaffold_uses_promoted_tactic_names(self) -> None:
        """Tactic names in the scaffold must come from the promoted version, not the baseline."""
        skeleton = attack.build_identity_version_map("MITRE ATT&CK", BASELINE, PROMOTED)
        promoted_lookups = attack.build_attack_lookups_for_version(PROMOTED)
        promoted_tactic_id_to_name = {v: k for k, v in promoted_lookups.tactics_map.items()}
        for tactic_id, entry in skeleton["tactics"].items():
            if tactic_id in promoted_tactic_id_to_name:
                self.assertEqual(
                    entry["name"],
                    promoted_tactic_id_to_name[tactic_id],
                    f"Scaffold tactic {tactic_id} has baseline name '{entry['name']}' "
                    f"instead of promoted name '{promoted_tactic_id_to_name[tactic_id]}'",
                )

    def test_scaffold_uses_promoted_technique_names(self) -> None:
        """Technique names that exist in the promoted version must reflect that version's name."""
        skeleton = attack.build_identity_version_map("MITRE ATT&CK", BASELINE, PROMOTED)
        promoted_lookups = attack.build_attack_lookups_for_version(PROMOTED)
        for technique_id, entry in skeleton["techniques"].items():
            if technique_id in promoted_lookups.technique_lookup:
                expected = promoted_lookups.technique_lookup[technique_id]["name"]
                self.assertEqual(
                    entry["name"],
                    expected,
                    f"Scaffold technique {technique_id} has name '{entry['name']}' instead of '{expected}'",
                )


class TestBuildThreatMapEntry(unittest.TestCase):
    """Threat entries built from technique IDs."""

    def test_defense_evasion_name_resolves(self) -> None:
        """The baseline tactic name still builds an entry after the TA0005 rename."""
        entry = attack.build_threat_map_entry("Defense Evasion", "T1055")
        self.assertEqual(entry["tactic"]["id"], "TA0005")
        self.assertEqual(entry["tactic"]["name"], "Defense Evasion")
        self.assertEqual(entry["technique"][0]["id"], "T1055")

    def test_defense_evasion_alias_when_tactic_is_renamed(self) -> None:
        """A dataset that only has the renamed tactic still accepts the baseline tactic name."""
        tactic_id = attack.tactics_map["Defense Evasion"]
        techniques = list(attack.matrix["Defense Evasion"])
        with (
            mock.patch.dict(attack.tactics_map, {"Stealth": tactic_id}, clear=True),
            mock.patch.dict(attack.matrix, {"Stealth": techniques}, clear=True),
        ):
            entry = attack.build_threat_map_entry("Defense Evasion", "T1055")
        self.assertEqual(entry["tactic"]["id"], "TA0005")
        self.assertEqual(entry["tactic"]["name"], "Defense Evasion")

    def test_redirect_that_changes_tactic_keeps_original_id(self) -> None:
        """A replacement filed under another tactic does not rewrite the baseline entry."""
        entry = attack.build_threat_map_entry("Persistence", "T1547.011")
        sub_ids = [sub["id"] for tech in entry["technique"] for sub in tech.get("subtechnique", [])]
        self.assertIn("T1547.011", sub_ids)
        self.assertNotIn("T1647", sub_ids)
        self.assertEqual(entry["tactic"]["name"], "Persistence")


if __name__ == "__main__":
    unittest.main()

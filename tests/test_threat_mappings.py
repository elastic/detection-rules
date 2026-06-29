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
    return {
        "creation_date": "2020/12/15",
        "integration": ["endpoint"],
        "maturity": "production",
        "min_stack_comments": "test",
        "min_stack_version": "8.3.0",
        "updated_date": "2024/08/30",
    }


def _rule(threat_mappings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
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


class TestVersionedThreatMappingSchema(unittest.TestCase):
    """Schema validation + build-time selection for `threat_mappings`."""

    def _load(self, rule_dict: dict[str, Any]):
        return RuleCollection().load_dict({"metadata": _metadata(), "rule": rule_dict})

    def test_loads_and_round_trips(self) -> None:
        rule = self._load(_rule(threat_mappings=[_v19_block()]))
        self.assertEqual(len(rule.contents.data.threat_mappings), 1)
        self.assertEqual(rule.contents.data.threat_mappings[0].version, "19")

    def test_default_emits_baseline_and_strips_field(self) -> None:
        rule = self._load(_rule(threat_mappings=[_v19_block()]))
        with ThreatMappingEnv(None):
            api = rule.contents.to_api_format()
        self.assertNotIn("threat_mappings", api)
        self.assertEqual(api["threat"][0]["technique"][0]["name"], "Valid Accounts")

    def test_selects_v19_when_configured(self) -> None:
        rule = self._load(_rule(threat_mappings=[_v19_block()]))
        with ThreatMappingEnv("19"):
            api = rule.contents.to_api_format()
        self.assertNotIn("threat_mappings", api)
        self.assertEqual(api["threat"][0]["technique"][0]["name"], "Valid Accounts (v19)")

    def test_missing_version_falls_back_to_default(self) -> None:
        rule = self._load(_rule(threat_mappings=[_v19_block()]))
        with ThreatMappingEnv("20"):
            api = rule.contents.to_api_format()
        self.assertEqual(api["threat"][0]["technique"][0]["name"], "Valid Accounts")

    def test_duplicate_framework_version_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            self._load(_rule(threat_mappings=[_v19_block(), _v19_block()]))

    def test_inner_framework_mismatch_rejected(self) -> None:
        block = _v19_block()
        block["threat"][0]["framework"] = "MITRE ATLAS"
        with self.assertRaises(ValidationError):
            self._load(_rule(threat_mappings=[block]))


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
        import yaml

        path = directory / name
        path.write_text(yaml.safe_dump(data))
        return path

    def test_parse_and_lookup(self) -> None:
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
        with TemporaryDirectory() as tmp:
            self._write(Path(tmp), "m.yaml", self.MAP)
            vmap = attack.get_attack_version_map("MITRE ATT&CK", "18", "19", [Path(tmp)])
            self.assertEqual(vmap.target_version, "19")
            with self.assertRaises(ValueError):
                attack.get_attack_version_map("MITRE ATT&CK", "18", "99", [Path(tmp)])

    def test_missing_required_keys_rejected(self) -> None:
        with TemporaryDirectory() as tmp:
            path = self._write(Path(tmp), "bad.yaml", {"framework": "MITRE ATT&CK"})
            with self.assertRaises(ValueError):
                attack.parse_attack_version_map(path)

    def test_malformed_destination_rejected(self) -> None:
        bad = dict(self.MAP)
        bad["techniques"] = {"T1078": {"id": "T1078"}}  # missing name/reference
        with TemporaryDirectory() as tmp:
            path = self._write(Path(tmp), "bad.yaml", bad)
            with self.assertRaises(ValueError):
                attack.parse_attack_version_map(path)

    def test_duplicate_triple_rejected(self) -> None:
        with TemporaryDirectory() as tmp:
            self._write(Path(tmp), "a.yaml", self.MAP)
            self._write(Path(tmp), "b.yaml", self.MAP)
            with self.assertRaises(ValueError):
                attack.load_attack_version_maps([Path(tmp)])


class TestIdentityScaffold(unittest.TestCase):
    def test_build_identity_version_map(self) -> None:
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


if __name__ == "__main__":
    unittest.main()

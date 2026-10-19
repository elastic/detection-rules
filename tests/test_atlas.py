# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Tests for versioned MITRE ATLAS data loading and threat map construction."""

import unittest

from detection_rules import atlas


class TestAtlasLookups(unittest.TestCase):
    """ATLAS versioned data and lookup helpers."""

    def test_current_version_is_loaded(self) -> None:
        """The latest atlas-v*.json.gz file is the current content version."""
        self.assertNotEqual(atlas.CURRENT_ATLAS_VERSION, "unknown")
        lookups = atlas.build_atlas_lookups_for_version(atlas.CURRENT_ATLAS_VERSION)
        self.assertGreater(len(lookups.tactics_map), 0)
        self.assertGreater(len(lookups.technique_lookup), 0)
        self.assertIn("AML.T0051", lookups.technique_lookup)

    def test_canonical_technique_id(self) -> None:
        """Short Txxxx tags and AML.Txxxx IDs both normalize to AML.Txxxx."""
        self.assertEqual(atlas.canonical_technique_id("T0085"), "AML.T0085")
        self.assertEqual(atlas.canonical_technique_id("AML.T0085.001"), "AML.T0085.001")
        self.assertEqual(atlas.canonical_technique_id("T0085.001"), "AML.T0085.001")

    def test_build_threat_map_entry_uses_atlas_urls(self) -> None:
        """ATLAS references keep dotted IDs (not ATT&CK-style slash-split paths)."""
        entry = atlas.build_threat_map_entry("Execution", "AML.T0051")
        self.assertEqual(entry["framework"], "MITRE ATLAS")
        self.assertEqual(entry["tactic"]["id"], "AML.TA0005")
        self.assertEqual(entry["tactic"]["reference"], "https://atlas.mitre.org/tactics/AML.TA0005/")
        self.assertEqual(entry["technique"][0]["id"], "AML.T0051")
        self.assertEqual(entry["technique"][0]["reference"], "https://atlas.mitre.org/techniques/AML.T0051/")

    def test_subtechnique_nests_under_parent(self) -> None:
        """AML.Txxxx.yyy is nested under the parent technique."""
        entry = atlas.build_threat_map_entry("Collection", "AML.T0085.001")
        parent = entry["technique"][0]
        self.assertEqual(parent["id"], "AML.T0085")
        self.assertEqual(parent["subtechnique"][0]["id"], "AML.T0085.001")
        self.assertEqual(
            parent["subtechnique"][0]["reference"],
            "https://atlas.mitre.org/techniques/AML.T0085.001/",
        )

    def test_unknown_technique_raises(self) -> None:
        """Unknown or OWASP-style IDs are rejected."""
        with self.assertRaises(ValueError):
            atlas.build_threat_map_entry("Impact", "LLM04")

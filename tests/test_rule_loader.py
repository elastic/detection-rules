# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test RawRuleCollection loading and CLI flag backwards compatibility."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from detection_rules.kbwrap import kibana_export_rules
from detection_rules.main import import_rules_into_repo
from detection_rules.rule_loader import RawRuleCollection

DUPLICATE_NAME = "Duplicate Name Rule"
ACTIVE_RULE_ID = "11111111-1111-4111-8111-111111111111"
DEPRECATED_RULE_ID = "22222222-2222-4222-8222-222222222222"


def build_rule_dict(rule_id: str, name: str, maturity: str) -> dict[str, Any]:
    """Build a minimal raw rule dict for RawRuleCollection tests."""
    metadata: dict[str, Any] = {"creation_date": "2020/01/01", "updated_date": "2020/01/01", "maturity": maturity}
    if maturity == "deprecated":
        metadata["deprecation_date"] = "2024/01/01"

    return {
        "metadata": metadata,
        "rule": {"rule_id": rule_id, "name": name, "description": "Test rule"},
    }


class TestRawRuleCollectionDeprecatedSplit(unittest.TestCase):
    """RawRuleCollection should allow an active and deprecated rule to share a name."""

    def test_active_and_deprecated_rule_can_share_a_name(self) -> None:
        """A deprecated rule should not collide with an active rule of the same name."""
        collection = RawRuleCollection()
        active = collection.load_dict(build_rule_dict(ACTIVE_RULE_ID, DUPLICATE_NAME, "production"))
        deprecated = collection.load_dict(build_rule_dict(DEPRECATED_RULE_ID, DUPLICATE_NAME, "deprecated"))

        self.assertIn(active, collection.rules)
        self.assertIn(deprecated, collection.deprecated.rules)
        self.assertEqual(collection.name_map[DUPLICATE_NAME].id, ACTIVE_RULE_ID)
        self.assertEqual(collection.deprecated.name_map[DUPLICATE_NAME].id, DEPRECATED_RULE_ID)

    def test_two_active_rules_with_same_name_still_collide(self) -> None:
        """Name collision detection between two active rules should be unaffected."""
        collection = RawRuleCollection()
        _ = collection.load_dict(build_rule_dict(ACTIVE_RULE_ID, DUPLICATE_NAME, "production"))

        with self.assertRaises(ValueError):
            _ = collection.load_dict(build_rule_dict(DEPRECATED_RULE_ID, DUPLICATE_NAME, "production"))

    def test_two_deprecated_rules_with_same_name_still_collide(self) -> None:
        """Name collision detection between two deprecated rules should be unaffected."""
        collection = RawRuleCollection()
        _ = collection.load_dict(build_rule_dict(ACTIVE_RULE_ID, DUPLICATE_NAME, "deprecated"))

        with self.assertRaises(ValueError):
            _ = collection.load_dict(build_rule_dict(DEPRECATED_RULE_ID, DUPLICATE_NAME, "deprecated"))

    def test_load_file_from_directory_with_shared_name(self) -> None:
        """Loading two files from disk with a shared name should not raise, mirroring the DaC bug report."""
        with TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            active_path = tmp / "active_rule.toml"
            deprecated_path = tmp / "deprecated_rule.toml"

            _ = active_path.write_text(
                '[metadata]\ncreation_date = "2020/01/01"\nupdated_date = "2020/01/01"\n'
                'maturity = "production"\n\n[rule]\n'
                f'rule_id = "{ACTIVE_RULE_ID}"\nname = "{DUPLICATE_NAME}"\ndescription = "Active version"\n'
            )
            _ = deprecated_path.write_text(
                '[metadata]\ncreation_date = "2020/01/01"\nupdated_date = "2024/01/01"\n'
                'deprecation_date = "2024/01/01"\nmaturity = "deprecated"\n\n[rule]\n'
                f'rule_id = "{DEPRECATED_RULE_ID}"\nname = "{DUPLICATE_NAME}"\ndescription = "Deprecated version"\n'
            )

            collection = RawRuleCollection()
            collection.load_directory(tmp)

            self.assertEqual(len(collection.rules), 1)
            self.assertEqual(len(collection.deprecated.rules), 1)


class TestLoadRuleLoadingFlagBackwardsCompatibility(unittest.TestCase):
    """--load-rule-loading / -lr must keep working as deprecated aliases for --use-existing-rule-dirs."""

    def test_import_rules_into_repo_accepts_old_flag(self) -> None:
        """The old --load-rule-loading and -lr flags must still enable use_existing_rule_dirs."""
        for args in (["--load-rule-loading"], ["-lr"], ["--use-existing-rule-dirs"]):
            ctx = import_rules_into_repo.make_context("import-rules-into-repo", list(args))
            self.assertTrue(ctx.params["use_existing_rule_dirs"], f"failed for args: {args}")

        ctx = import_rules_into_repo.make_context("import-rules-into-repo", [])
        self.assertFalse(ctx.params["use_existing_rule_dirs"])

    def test_kibana_export_rules_accepts_old_flag(self) -> None:
        """The old --load-rule-loading and -lr flags must still enable use_existing_rule_dirs."""
        base_args = ["--directory", "export-rules-test"]
        for flag in (["--load-rule-loading"], ["-lr"], ["--use-existing-rule-dirs"], ["-ud"]):
            ctx = kibana_export_rules.make_context("export-rules", [*base_args, *flag])
            self.assertTrue(ctx.params["use_existing_rule_dirs"], f"failed for flag: {flag}")

        ctx = kibana_export_rules.make_context("export-rules", base_args)
        self.assertFalse(ctx.params["use_existing_rule_dirs"])

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test that the packages are built correctly."""

import unittest
import uuid

from marshmallow import ValidationError
from semver import Version

from detection_rules import rule_loader
from detection_rules.packaging import PACKAGE_FILE, Package
from detection_rules.schemas.registry_package import RegistryPackageManifestV1, RegistryPackageManifestV3
from tests.base import BaseRuleTest

package_configs = Package.load_configs()


class TestPackages(BaseRuleTest):
    """Test package building and saving."""

    @staticmethod
    def get_test_rule(version=1, count=1):
        def get_rule_contents():
            return {
                "author": ["Elastic"],
                "description": "test description",
                "language": "kuery",
                "license": "Elastic License v2",
                "name": "test rule",
                "query": "process.name:test.query",
                "risk_score": 21,
                "rule_id": str(uuid.uuid4()),
                "severity": "low",
                "type": "query",
            }

        rules = [rule_loader.TOMLRule("test.toml", get_rule_contents()) for i in range(count)]
        version_info = {
            rule.id: {"rule_name": rule.name, "sha256": rule.contents.get_hash(), "version": version} for rule in rules
        }

        return rules, version_info

    def test_package_loader_production_config(self):
        """Test that packages are loading correctly."""

    @unittest.skipIf(rule_loader.RULES_CONFIG.bypass_version_lock, "Version lock bypassed")
    def test_package_loader_default_configs(self):
        """Test configs in detection_rules/etc/packages.yaml."""
        Package.from_config(rule_collection=self.rc, config=package_configs)

    @unittest.skipIf(rule_loader.RULES_CONFIG.bypass_version_lock, "Version lock bypassed")
    def test_package_summary(self):
        """Test the generation of the package summary."""
        rules = self.rc
        package = Package(rules, "test-package")
        package.generate_summary_and_changelog(package.changed_ids, package.new_ids, package.removed_ids)

    @unittest.skipIf(rule_loader.RULES_CONFIG.bypass_version_lock, "Version lock bypassed")
    def test_rule_versioning(self):
        """Test that all rules are properly versioned and tracked"""
        self.maxDiff = None
        rules = self.rc
        original_hashes = []

        # test that no rules have versions defined
        for rule in rules:
            self.assertGreaterEqual(rule.contents.autobumped_version, 1, "{} - {}: version is not being set in package")
            original_hashes.append(rule.contents.get_hash())

        package = Package(rules, "test-package")

        # test that all rules have versions defined
        for rule in package.rules:
            self.assertGreaterEqual(rule.contents.autobumped_version, 1, "{} - {}: version is not being set in package")

        # test that rules validate with version

        post_bump_hashes = [rule.contents.get_hash() for rule in package.rules]

        # test that no hashes changed as a result of the version bumps
        self.assertListEqual(original_hashes, post_bump_hashes, "Version bumping modified the hash of a rule")


class TestRegistryPackage(unittest.TestCase):
    """Test the OOB registry package."""

    @classmethod
    def setUpClass(cls) -> None:
        assert "registry_data" in package_configs, f"Missing registry_data in {PACKAGE_FILE}"
        cls.registry_config = package_configs["registry_data"]
        stack_version = Version.parse(
            cls.registry_config["conditions"]["kibana.version"].strip("^"), optional_minor_and_patch=True
        )
        if stack_version >= Version.parse("8.12.0"):
            RegistryPackageManifestV3.from_dict(cls.registry_config)
        else:
            RegistryPackageManifestV1.from_dict(cls.registry_config)

    def test_registry_package_config(self):
        """Test that the registry package is validating properly."""
        registry_config = self.registry_config.copy()
        registry_config["version"] += "7.1.1."

        with self.assertRaises(ValidationError):
            RegistryPackageManifestV1.from_dict(registry_config)

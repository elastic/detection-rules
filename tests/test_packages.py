# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test that the packages are built correctly."""
import unittest
import uuid

from detection_rules import rule_loader
from detection_rules.packaging import PACKAGE_FILE, Package
from detection_rules.rule_loader import RuleCollection
from tests.base import BaseRuleTest

package_configs = Package.load_configs()


class TestPackages(BaseRuleTest):
    """Test package building and saving."""

    @staticmethod
    def get_test_rule(version=1, count=1):
        def get_rule_contents():
            contents = {
                "author": ["Elastic"],
                "description": "test description",
                "language": "kuery",
                "license": "Elastic License v2",
                "name": "test rule",
                "query": "process.name:test.query",
                "risk_score": 21,
                "rule_id": str(uuid.uuid4()),
                "severity": "low",
                "type": "query"
            }
            return contents

        rules = [rule_loader.TOMLRule('test.toml', get_rule_contents()) for i in range(count)]
        version_info = {
            rule.id: {
                'rule_name': rule.name,
                'sha256': rule.contents.sha256(),
                'version': version
            } for rule in rules
        }

        return rules, version_info

    def test_package_loader_production_config(self):
        """Test that packages are loading correctly."""

    def test_package_loader_default_configs(self):
        """Test configs in etc/packages.yml."""
        Package.from_config(package_configs)

    def test_package_summary(self):
        """Test the generation of the package summary."""
        rules = self.production_rules
        package = Package(rules, 'test-package')
        changed_rule_ids, new_rule_ids, deprecated_rule_ids = package.bump_versions(save_changes=False)
        package.generate_summary_and_changelog(changed_rule_ids, new_rule_ids, deprecated_rule_ids)

    # def test_versioning_diffs(self):
    #     """Test that versioning is detecting diffs as expected."""
    #     rules, version_info = self.get_test_rule()
    #     package = Package(rules, 'test', current_versions=version_info)
    #
    #     # test versioning doesn't falsely detect changes
    #     changed_rules, new_rules = package.changed_rule_ids, package.new_rules_ids
    #
    #     self.assertEqual(0, len(changed_rules), 'Package version bumping is improperly detecting changed rules')
    #     self.assertEqual(0, len(new_rules), 'Package version bumping is improperly detecting new rules')
    #     self.assertEqual(1, package.rules[0].contents['version'], 'Package version bumping unexpectedly')
    #
    #     # test versioning detects a new rule
    #     package.rules[0].contents.pop('version')
    #     changed_rules, new_rules, _ = package.bump_versions(current_versions={})
    #
    #     self.assertEqual(0, len(changed_rules), 'Package version bumping is improperly detecting changed rules')
    #     self.assertEqual(1, len(new_rules), 'Package version bumping is not detecting new rules')
    #     self.assertEqual(1, package.rules[0].contents['version'],
    #                      'Package version bumping not setting version to 1 for new rules')
    #
    #     # test versioning detects a hash changes
    #     package.rules[0].contents.pop('version')
    #     package.rules[0].contents['query'] = 'process.name:changed.test.query'
    #     changed_rules, new_rules, _ = package.bump_versions(current_versions=version_info)
    #
    #     self.assertEqual(1, len(changed_rules), 'Package version bumping is not detecting changed rules')
    #     self.assertEqual(0, len(new_rules), 'Package version bumping is improperly detecting new rules')
    #     self.assertEqual(2, package.rules[0].contents['version'], 'Package version not bumping on changes')

    def test_rule_versioning(self):
        """Test that all rules are properly versioned and tracked"""
        self.maxDiff = None
        rules = RuleCollection.default()
        original_hashes = []
        post_bump_hashes = []

        # test that no rules have versions defined
        for rule in rules:
            self.assertGreaterEqual(rule.contents.autobumped_version, 1, '{} - {}: version is not being set in package')
            original_hashes.append(rule.contents.sha256())

        package = Package(rules, 'test-package')

        # test that all rules have versions defined
        # package.bump_versions(save_changes=False)
        for rule in package.rules:
            self.assertGreaterEqual(rule.contents.autobumped_version, 1, '{} - {}: version is not being set in package')

        # test that rules validate with version
        for rule in package.rules:
            post_bump_hashes.append(rule.contents.sha256())

        # test that no hashes changed as a result of the version bumps
        self.assertListEqual(original_hashes, post_bump_hashes, 'Version bumping modified the hash of a rule')

    # def test_version_filter(self):
    #     """Test that version filtering is working as expected."""
    #     msg = 'Package version filter failing'
    #
    #     rules, version_info = self.get_test_rule(version=1, count=3)
    #     package = Package(rules, 'test', current_versions=version_info, min_version=2)
    #     self.assertEqual(0, len(package.rules), msg)
    #
    #     rules, version_info = self.get_test_rule(version=5, count=3)
    #     package = Package(rules, 'test', current_versions=version_info, max_version=2)
    #     self.assertEqual(0, len(package.rules), msg)
    #
    #     rules, version_info = self.get_test_rule(version=2, count=3)
    #     package = Package(rules, 'test', current_versions=version_info, min_version=1, max_version=3)
    #     self.assertEqual(3, len(package.rules), msg)
    #
    #     rules, version_info = self.get_test_rule(version=1, count=3)
    #
    #     version = 1
    #     for rule_id, vinfo in version_info.items():
    #         vinfo['version'] = version
    #         version += 1
    #
    #     package = Package(rules, 'test', current_versions=version_info, min_version=2, max_version=2)
    #     self.assertEqual(1, len(package.rules), msg)


class TestRegistryPackage(unittest.TestCase):
    """Test the OOB registry package."""

    @classmethod
    def setUpClass(cls) -> None:
        from detection_rules.schemas.registry_package import RegistryPackageManifest

        assert 'registry_data' in package_configs, f'Missing registry_data in {PACKAGE_FILE}'
        cls.registry_config = package_configs['registry_data']
        RegistryPackageManifest.from_dict(cls.registry_config)

    def test_registry_package_config(self):
        """Test that the registry package is validating properly."""
        from marshmallow import ValidationError
        from detection_rules.schemas.registry_package import RegistryPackageManifest

        registry_config = self.registry_config.copy()
        registry_config['version'] += '7.1.1.'

        with self.assertRaises(ValidationError):
            RegistryPackageManifest.from_dict(registry_config)

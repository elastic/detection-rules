# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Test that all rules have valid metadata and syntax."""
import json
import os
import re
import sys
import unittest
import warnings
from collections import defaultdict

import jsonschema
import kql
import toml
import pytoml
from rta import get_ttp_names

from detection_rules import attack, rule_loader
from detection_rules.utils import load_etc_dump
from detection_rules.rule import Rule


class TestValidRules(unittest.TestCase):
    """Test that all detection rules load properly without duplicates."""

    def test_schema_and_dupes(self):
        """Ensure that every rule matches the schema and there are no duplicates."""
        rule_files = rule_loader.load_rule_files()
        self.assertGreaterEqual(len(rule_files), 1, 'No rules were loaded from rules directory!')

    def test_all_rule_files(self):
        """Ensure that every rule file can be loaded and validate against schema."""
        rules = []

        for file_name, contents in rule_loader.load_rule_files().items():
            try:
                rule = Rule(file_name, contents)
                rules.append(rule)

            except (pytoml.TomlError, toml.TomlDecodeError) as e:
                print("TOML error when parsing rule file \"{}\"".format(os.path.basename(file_name)), file=sys.stderr)
                raise e

            except jsonschema.ValidationError as e:
                print("Schema error when parsing rule file \"{}\"".format(os.path.basename(file_name)), file=sys.stderr)
                raise e

    def test_rule_loading(self):
        """Ensure that all rule queries have ecs version."""
        rule_loader.load_rules().values()

    def test_file_names(self):
        """Test that the file names meet the requirement."""
        file_pattern = rule_loader.FILE_PATTERN

        self.assertIsNone(re.match(file_pattern, 'NotValidRuleFile.toml'),
                          'Incorrect pattern for verifying rule names: {}'.format(file_pattern))
        self.assertIsNone(re.match(file_pattern, 'still_not_a_valid_file_name.not_json'),
                          'Incorrect pattern for verifying rule names: {}'.format(file_pattern))

        for rule_file in rule_loader.load_rule_files().keys():
            self.assertIsNotNone(re.match(file_pattern, os.path.basename(rule_file)),
                                 'Invalid file name for {}'.format(rule_file))

    def test_all_rules_as_rule_schema(self):
        """Ensure that every rule file validates against the rule schema."""
        for file_name, contents in rule_loader.load_rule_files().items():
            rule = Rule(file_name, contents)
            rule.validate(as_rule=True)

    def test_all_rule_queries_optimized(self):
        """Ensure that every rule query is in optimized form."""
        for file_name, contents in rule_loader.load_rule_files().items():
            rule = Rule(file_name, contents)

            if rule.query and rule.contents['language'] == 'kuery':
                tree = kql.parse(rule.query, optimize=False)
                optimized = tree.optimize(recursive=True)
                err_message = '\nQuery not optimized for rule: {} - {}\nExpected: {}\nActual:   {}'.format(
                    rule.name, rule.id, optimized, rule.query)
                self.assertEqual(tree, optimized, err_message)

    def test_no_unrequired_defaults(self):
        """Test that values that are not required in the schema are not set with default values."""
        rules_with_hits = {}

        for file_name, contents in rule_loader.load_rule_files().items():
            rule = Rule(file_name, contents)
            default_matches = rule_loader.find_unneeded_defaults(rule)

            if default_matches:
                rules_with_hits['{} - {}'.format(rule.name, rule.id)] = default_matches

        error_msg = 'The following rules have unnecessary default values set: \n{}'.format(
            json.dumps(rules_with_hits, indent=2))
        self.assertDictEqual(rules_with_hits, {}, error_msg)

    @rule_loader.mock_loader
    def test_production_rules_have_rta(self):
        """Ensure that all production rules have RTAs."""
        mappings = load_etc_dump('rule-mapping.yml')

        ttp_names = get_ttp_names()

        for rule in rule_loader.get_production_rules():
            if rule.type == 'query' and rule.id in mappings:
                matching_rta = mappings[rule.id].get('rta_name')

                self.assertIsNotNone(matching_rta, "Rule {} ({}) does not have RTAs".format(rule.name, rule.id))

                rta_name, ext = os.path.splitext(matching_rta)
                if rta_name not in ttp_names:
                    self.fail("{} ({}) references unknown RTA: {}".format(rule.name, rule.id, rta_name))

    def test_duplicate_file_names(self):
        """Test that no file names are duplicated."""
        name_map = defaultdict(list)
        for file_path in rule_loader.load_rule_files():
            base_name = os.path.basename(file_path)
            name_map[base_name].append(file_path)

        duplicates = {name: paths for name, paths in name_map.items() if len(paths) > 1}
        if duplicates:
            self.fail(f"Found duplicated file names {duplicates}")


class TestThreatMappings(unittest.TestCase):
    """Test threat mapping data for rules."""

    def test_tactic_to_technique_correlations(self):
        """Ensure rule threat info is properly related to a single tactic and technique."""
        rules = rule_loader.load_rules().values()

        for rule in rules:
            threat_mapping = rule.contents.get('threat')
            if threat_mapping:
                for entry in threat_mapping:
                    tactic = entry.get('tactic')
                    techniques = entry.get('technique', [])
                    expected_tactic = attack.tactics_map[tactic['name']]
                    self.assertEqual(expected_tactic, tactic['id'],
                                     f'ATT&CK tactic mapping error for rule: {rule.id} - {rule.name} ->\n'
                                     f'expected:  {expected_tactic} for {tactic["name"]}\n'
                                     f'actual: {tactic["id"]}')

                    for technique in techniques:
                        expected_technique = attack.technique_lookup[technique['id']]['name']
                        self.assertEqual(expected_technique, technique['name'],
                                         f'ATT&CK technique mapping error for rule: {rule.id} - {rule.name} ->\n'
                                         f'expected: {expected_technique} for {technique["id"]}\n'
                                         f'actual: {technique["name"]}')

    def test_technique_deprecations(self):
        """Check and warn for use of any ATT&CK techniques that have been deprecated."""
        deprecated = {}  # {technique: rules_using_them
        rules = rule_loader.load_rules().values()

        for rule in rules:
            rule_info = f'{rule.id} - {rule.name}'
            threat_mapping = rule.contents.get('threat')

            if threat_mapping:
                for entry in threat_mapping:
                    techniques = entry.get('technique', [])
                    for technique in techniques:
                        if technique['id'] in attack.revoked:
                            deprecated.setdefault(technique['id'], [])
                            deprecated[technique['id']].append(rule_info)

        if deprecated:
            deprecated_str = json.dumps(deprecated, indent=2, sort_keys=True)
            mitre_url = 'https://attack.mitre.org/resources/updates/'
            warning_str = f'The following rules are using deprecated ATT&CK techniques ({mitre_url}):\n{deprecated_str}'
            warnings.warn(warning_str)

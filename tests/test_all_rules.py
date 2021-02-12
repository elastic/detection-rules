# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test that all rules have valid metadata and syntax."""
import json
import os
import re
import sys
import unittest
from collections import defaultdict
from pathlib import Path

import jsonschema
import kql
import toml
import pytoml
from rta import get_ttp_names

from detection_rules import attack, beats, ecs, rule_loader
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
        """Ensure that all rules validate."""
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
            default_matches = rule_loader.find_unneeded_defaults_from_rule(rule)

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

    def test_technique_deprecations(self):
        """Check for use of any ATT&CK techniques that have been deprecated."""
        replacement_map = attack.techniques_redirect_map
        revoked = list(attack.revoked)
        deprecated = list(attack.deprecated)
        rules = rule_loader.load_rules().values()

        for rule in rules:
            revoked_techniques = {}
            rule_info = f'{rule.id} - {rule.name}'
            threat_mapping = rule.contents.get('threat')

            if threat_mapping:
                for entry in threat_mapping:
                    techniques = entry.get('technique', [])
                    for technique in techniques:
                        if technique['id'] in revoked + deprecated:
                            revoked_techniques[technique['id']] = replacement_map.get(technique['id'],
                                                                                      'DEPRECATED - DO NOT USE')

            if revoked_techniques:
                old_new_mapping = "\n".join(f'Actual: {k} -> Expected {v}' for k, v in revoked_techniques.items())
                self.fail(f'{rule_info} -> Using deprecated ATT&CK techniques: \n{old_new_mapping}')

    def test_tactic_to_technique_correlations(self):
        """Ensure rule threat info is properly related to a single tactic and technique."""
        rules = rule_loader.load_rules().values()

        for rule in rules:
            threat_mapping = rule.contents.get('threat')
            if threat_mapping:
                for entry in threat_mapping:
                    tactic = entry.get('tactic')
                    techniques = entry.get('technique', [])

                    mismatched = [t['id'] for t in techniques if t['id'] not in attack.matrix[tactic['name']]]
                    if mismatched:
                        self.fail(f'mismatched ATT&CK techniques for rule: {rule.id} - {rule.name} -> '
                                  f'{", ".join(mismatched)} not under: {tactic["name"]}')

                    # tactic
                    expected_tactic = attack.tactics_map[tactic['name']]
                    self.assertEqual(expected_tactic, tactic['id'],
                                     f'ATT&CK tactic mapping error for rule: {rule.id} - {rule.name} ->\n'
                                     f'expected:  {expected_tactic} for {tactic["name"]}\n'
                                     f'actual: {tactic["id"]}')

                    tactic_reference_id = tactic['reference'].rstrip('/').split('/')[-1]
                    self.assertEqual(tactic['id'], tactic_reference_id,
                                     f'ATT&CK tactic mapping error for rule: {rule.id} - {rule.name} ->\n'
                                     f'tactic ID {tactic["id"]} does not match the reference URL ID '
                                     f'{tactic["reference"]}')

                    # techniques
                    for technique in techniques:
                        expected_technique = attack.technique_lookup[technique['id']]['name']
                        self.assertEqual(expected_technique, technique['name'],
                                         f'ATT&CK technique mapping error for rule: {rule.id} - {rule.name} ->\n'
                                         f'expected: {expected_technique} for {technique["id"]}\n'
                                         f'actual: {technique["name"]}')

                        technique_reference_id = technique['reference'].rstrip('/').split('/')[-1]
                        self.assertEqual(technique['id'], technique_reference_id,
                                         f'ATT&CK technique mapping error for rule: {rule.id} - {rule.name} ->\n'
                                         f'technique ID {technique["id"]} does not match the reference URL ID '
                                         f'{technique["reference"]}')

                        # sub-techniques
                        sub_techniques = technique.get('subtechnique')
                        if sub_techniques:
                            for sub_technique in sub_techniques:
                                expected_sub_technique = attack.technique_lookup[sub_technique['id']]['name']
                                self.assertEqual(expected_sub_technique, sub_technique['name'],
                                                 f'ATT&CK sub-technique mapping error for rule: {rule.id} - {rule.name} ->\n'  # noqa: E501
                                                 f'expected: {expected_sub_technique} for {sub_technique["id"]}\n'
                                                 f'actual: {sub_technique["name"]}')

                                sub_technique_reference_id = '.'.join(
                                    sub_technique['reference'].rstrip('/').split('/')[-2:])
                                self.assertEqual(sub_technique['id'], sub_technique_reference_id,
                                                 f'ATT&CK sub-technique mapping error for rule: {rule.id} - {rule.name} ->\n'  # noqa: E501
                                                 f'sub-technique ID {sub_technique["id"]} does not match the reference URL ID '  # noqa: E501
                                                 f'{sub_technique["reference"]}')

    def test_duplicated_tactics(self):
        """Check that a tactic is only defined once."""
        rules = rule_loader.load_rules().values()

        for rule in rules:
            rule_info = f'{rule.id} - {rule.name}'
            threat_mapping = rule.contents.get('threat', [])
            tactics = [t['tactic']['name'] for t in threat_mapping]
            duplicates = sorted(set(t for t in tactics if tactics.count(t) > 1))

            if duplicates:
                self.fail(f'{rule_info} -> duplicate tactics defined for {duplicates}. '
                          f'Flatten to a single entry per tactic')


class TestRuleTags(unittest.TestCase):
    """Test tags data for rules."""

    def test_casing_and_spacing(self):
        """Ensure consistent and expected casing for controlled tags."""
        rules = rule_loader.load_rules().values()

        def normalize(s):
            return ''.join(s.lower().split())

        expected_tags = [
            'APM', 'AWS', 'Asset Visibility', 'Azure', 'Configuration Audit', 'Continuous Monitoring',
            'Data Protection', 'Elastic', 'Endpoint Security', 'GCP', 'Identity and Access', 'Linux', 'Logging', 'ML',
            'macOS', 'Monitoring', 'Network', 'Okta', 'Packetbeat', 'Post-Execution', 'SecOps', 'Windows'
        ]
        expected_case = {normalize(t): t for t in expected_tags}

        for rule in rules:
            rule_tags = rule.contents.get('tags')
            if rule_tags:
                invalid_tags = {t: expected_case[normalize(t)] for t in rule_tags
                                if normalize(t) in list(expected_case) and t != expected_case[normalize(t)]}

                if invalid_tags:
                    error_msg = f'{rule.id} - {rule.name} -> Invalid casing for expected tags\n'
                    error_msg += f'Actual tags: {", ".join(invalid_tags)}\n'
                    error_msg += f'Expected tags: {", ".join(invalid_tags.values())}'
                    self.fail(error_msg)

    def test_required_tags(self):
        """Test that expected tags are present within rules."""
        rules = rule_loader.load_rules().values()

        # indexes considered; only those with obvious relationships included
        # 'apm-*-transaction*', 'auditbeat-*', 'endgame-*', 'filebeat-*', 'logs-*', 'logs-aws*',
        # 'logs-endpoint.alerts-*', 'logs-endpoint.events.*', 'logs-okta*', 'packetbeat-*', 'winlogbeat-*'

        required_tags_map = {
            'apm-*-transaction*': {'all': ['APM']},
            'auditbeat-*': {'any': ['Windows', 'macOS', 'Linux']},
            'endgame-*': {'all': ['Endpoint Security']},
            'logs-aws*': {'all': ['AWS']},
            'logs-endpoint.alerts-*': {'all': ['Endpoint Security']},
            'logs-endpoint.events.*': {'any': ['Windows', 'macOS', 'Linux', 'Host']},
            'logs-okta*': {'all': ['Okta']},
            'logs-windows.*': {'all': ['Windows']},
            'packetbeat-*': {'all': ['Network']},
            'winlogbeat-*': {'all': ['Windows']}
        }

        for rule in rules:
            rule_tags = rule.contents.get('tags', [])
            indexes = rule.contents.get('index', [])
            error_msg = f'{rule.id} - {rule.name} -> Missing tags:\nActual tags: {", ".join(rule_tags)}'

            consolidated_optional_tags = []
            is_missing_any_tags = False
            missing_required_tags = set()

            if 'Elastic' not in rule_tags:
                missing_required_tags.add('Elastic')

            for index in indexes:
                expected_tags = required_tags_map.get(index, {})
                expected_all = expected_tags.get('all', [])
                expected_any = expected_tags.get('any', [])

                existing_any_tags = [t for t in rule_tags if t in expected_any]
                if expected_any:
                    # consolidate optional any tags which are not in use
                    consolidated_optional_tags.extend(t for t in expected_any if t not in existing_any_tags)

                missing_required_tags.update(set(expected_all).difference(set(rule_tags)))
                is_missing_any_tags = expected_any and not set(expected_any) & set(existing_any_tags)

            consolidated_optional_tags = [t for t in consolidated_optional_tags if t not in missing_required_tags]
            error_msg += f'\nMissing all of: {", ".join(missing_required_tags)}' if missing_required_tags else ''
            error_msg += f'\nMissing any of: {", " .join(consolidated_optional_tags)}' if is_missing_any_tags else ''

            if missing_required_tags or is_missing_any_tags:
                self.fail(error_msg)


class TestRuleTimelines(unittest.TestCase):
    """Test timelines in rules are valid."""

    TITLES = {
        'db366523-f1c6-4c1f-8731-6ce5ed9e5717': 'Generic Endpoint Timeline',
        '91832785-286d-4ebe-b884-1a208d111a70': 'Generic Network Timeline',
        '76e52245-7519-4251-91ab-262fb1a1728c': 'Generic Process Timeline'
    }

    def test_timeline_has_title(self):
        """Ensure rules with timelines have a corresponding title."""
        for rule in rule_loader.load_rules().values():
            rule_str = f'{rule.id} - {rule.name}'
            timeline_id = rule.contents.get('timeline_id')
            timeline_title = rule.contents.get('timeline_title')

            if (timeline_title or timeline_id) and not (timeline_title and timeline_id):
                missing_err = f'{rule_str} -> timeline "title" and "id" required when timelines are defined'
                self.fail(missing_err)

            if timeline_id:
                unknown_id = f'{rule_str} -> Unknown timeline_id: {timeline_id}.'
                unknown_id += f' replace with {", ".join(self.TITLES)} or update this unit test with acceptable ids'
                self.assertIn(timeline_id, list(self.TITLES), unknown_id)

                unknown_title = f'{rule_str} -> unknown timeline_title: {timeline_title}'
                unknown_title += f' replace with {", ".join(self.TITLES.values())}'
                unknown_title += ' or update this unit test with acceptable titles'
                self.assertEqual(timeline_title, self.TITLES[timeline_id], )


class TestRuleFiles(unittest.TestCase):
    """Test the expected file names."""

    def test_rule_file_names_by_tactic(self):
        """Test to ensure rule files have the primary tactic prepended to the filename."""
        rules = rule_loader.load_rules().values()
        bad_name_rules = []

        for rule in rules:
            rule_path = Path(rule.path).resolve()
            filename = rule_path.name

            if rule_path.parent.name == 'ml':
                continue

            threat = rule.contents.get('threat', [])
            authors = rule.contents.get('author', [])

            if threat and 'Elastic' in authors:
                primary_tactic = threat[0]['tactic']['name']
                tactic_str = primary_tactic.lower().replace(' ', '_')

                if tactic_str != filename[:len(tactic_str)]:
                    bad_name_rules.append(f'{rule.id} - {Path(rule.path).name} -> expected: {tactic_str}')

        if bad_name_rules:
            error_msg = 'filename does not start with the primary tactic - update the tactic or the rule filename'
            rule_err_str = '\n'.join(bad_name_rules)
            self.fail(f'{error_msg}:\n{rule_err_str}')


class TestRuleMetadata(unittest.TestCase):
    """Test the metadata of rules."""

    def test_ecs_and_beats_opt_in_not_latest_only(self):
        """Test that explicitly defined opt-in validation is not only the latest versions to avoid stale tests."""
        rules = rule_loader.load_rules().values()

        for rule in rules:
            beats_version = rule.metadata.get('beats_version')
            ecs_versions = rule.metadata.get('ecs_versions', [])
            latest_beats = str(beats.get_max_version())
            latest_ecs = ecs.get_max_version()
            error_prefix = f'{rule.id} - {rule.name} ->'

            error_msg = f'{error_prefix} it is unnecessary to define the current latest beats version: {latest_beats}'
            self.assertNotEqual(latest_beats, beats_version, error_msg)

            if len(ecs_versions) == 1:
                error_msg = f'{error_prefix} it is unnecessary to define the current latest ecs version if only ' \
                            f'one version is specified: {latest_ecs}'
                self.assertNotIn(latest_ecs, ecs_versions, error_msg)

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test that all rules have valid metadata and syntax."""
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

import eql
import jsonschema
import kql
import toml
import pytoml
from rta import get_ttp_names

from detection_rules import attack, beats, ecs
from detection_rules.packaging import load_versions
from detection_rules.rule_loader import FILE_PATTERN, find_unneeded_defaults_from_rule
from detection_rules.utils import get_path, load_etc_dump
from detection_rules.rule import Rule

from .base import BaseRuleTest


class TestValidRules(BaseRuleTest):
    """Test that all detection rules load properly without duplicates."""

    def test_schema_and_dupes(self):
        """Ensure that every rule matches the schema and there are no duplicates."""
        self.assertGreaterEqual(len(self.rule_files), 1, 'No rules were loaded from rules directory!')

    def test_all_rule_files(self):
        """Ensure that every rule file can be loaded and validate against schema."""
        for file_name, contents in self.rule_files.items():
            try:
                Rule(file_name, contents)
            except (pytoml.TomlError, toml.TomlDecodeError) as e:
                print("TOML error when parsing rule file \"{}\"".format(os.path.basename(file_name)), file=sys.stderr)
                raise e
            except jsonschema.ValidationError as e:
                print("Schema error when parsing rule file \"{}\"".format(os.path.basename(file_name)), file=sys.stderr)
                raise e

    def test_file_names(self):
        """Test that the file names meet the requirement."""
        file_pattern = FILE_PATTERN

        self.assertIsNone(re.match(file_pattern, 'NotValidRuleFile.toml'),
                          f'Incorrect pattern for verifying rule names: {file_pattern}')
        self.assertIsNone(re.match(file_pattern, 'still_not_a_valid_file_name.not_json'),
                          f'Incorrect pattern for verifying rule names: {file_pattern}')

        for rule_file in self.rule_files.keys():
            self.assertIsNotNone(re.match(file_pattern, os.path.basename(rule_file)),
                                 f'Invalid file name for {rule_file}')

    def test_all_rules_as_rule_schema(self):
        """Ensure that every rule file validates against the rule schema."""
        rules_path = get_path('rules')

        for file_name, contents in self.rule_files.items():
            rule = Rule(file_name, contents)

            if rule.metadata['maturity'] == 'deprecated':
                continue

            try:
                rule.validate(as_rule=True)
            except jsonschema.ValidationError as exc:
                rule_path = Path(rule.path).relative_to(rules_path)
                exc.message = f'{rule_path} -> {exc}'
                raise exc

    def test_all_rule_queries_optimized(self):
        """Ensure that every rule query is in optimized form."""
        for file_name, contents in self.rule_files.items():
            rule = Rule(file_name, contents)

            if rule.query and rule.contents['language'] == 'kuery':
                tree = kql.parse(rule.query, optimize=False)
                optimized = tree.optimize(recursive=True)
                err_message = f'\n{self.rule_str(rule)} Query not optimized for rule\n' \
                              f'Expected: {optimized}\nActual: {rule.query}'
                self.assertEqual(tree, optimized, err_message)

    def test_no_unrequired_defaults(self):
        """Test that values that are not required in the schema are not set with default values."""
        rules_with_hits = {}

        for file_name, contents in self.rule_files.items():
            rule = Rule(file_name, contents)
            default_matches = find_unneeded_defaults_from_rule(rule)

            if default_matches:
                rules_with_hits[self.rule_str(rule)] = default_matches

        error_msg = f'The following rules have unnecessary default values set: ' \
                    f'\n{json.dumps(rules_with_hits, indent=2)}'
        self.assertDictEqual(rules_with_hits, {}, error_msg)

    def test_production_rules_have_rta(self):
        """Ensure that all production rules have RTAs."""
        mappings = load_etc_dump('rule-mapping.yml')
        ttp_names = get_ttp_names()

        for rule in self.production_rules:
            if rule.type == 'query' and rule.id in mappings:
                matching_rta = mappings[rule.id].get('rta_name')

                self.assertIsNotNone(matching_rta, f'{self.rule_str(rule)} does not have RTAs')

                rta_name, ext = os.path.splitext(matching_rta)
                if rta_name not in ttp_names:
                    self.fail(f'{self.rule_str(rule)} references unknown RTA: {rta_name}')

    def test_duplicate_file_names(self):
        """Test that no file names are duplicated."""
        name_map = defaultdict(list)
        for file_path in self.rule_files:
            base_name = os.path.basename(file_path)
            name_map[base_name].append(file_path)

        duplicates = {name: paths for name, paths in name_map.items() if len(paths) > 1}
        if duplicates:
            self.fail(f"Found duplicated file names {duplicates}")


class TestThreatMappings(BaseRuleTest):
    """Test threat mapping data for rules."""

    def test_technique_deprecations(self):
        """Check for use of any ATT&CK techniques that have been deprecated."""
        replacement_map = attack.techniques_redirect_map
        revoked = list(attack.revoked)
        deprecated = list(attack.deprecated)

        for rule in self.rules:
            revoked_techniques = {}
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
                self.fail(f'{self.rule_str(rule)} Using deprecated ATT&CK techniques: \n{old_new_mapping}')

    def test_tactic_to_technique_correlations(self):
        """Ensure rule threat info is properly related to a single tactic and technique."""
        for rule in self.rules:
            threat_mapping = rule.contents.get('threat')
            if threat_mapping:
                for entry in threat_mapping:
                    tactic = entry.get('tactic')
                    techniques = entry.get('technique', [])

                    mismatched = [t['id'] for t in techniques if t['id'] not in attack.matrix[tactic['name']]]
                    if mismatched:
                        self.fail(f'mismatched ATT&CK techniques for rule: {self.rule_str(rule)} '
                                  f'{", ".join(mismatched)} not under: {tactic["name"]}')

                    # tactic
                    expected_tactic = attack.tactics_map[tactic['name']]
                    self.assertEqual(expected_tactic, tactic['id'],
                                     f'ATT&CK tactic mapping error for rule: {self.rule_str(rule)}\n'
                                     f'expected:  {expected_tactic} for {tactic["name"]}\n'
                                     f'actual: {tactic["id"]}')

                    tactic_reference_id = tactic['reference'].rstrip('/').split('/')[-1]
                    self.assertEqual(tactic['id'], tactic_reference_id,
                                     f'ATT&CK tactic mapping error for rule: {self.rule_str(rule)}\n'
                                     f'tactic ID {tactic["id"]} does not match the reference URL ID '
                                     f'{tactic["reference"]}')

                    # techniques
                    for technique in techniques:
                        expected_technique = attack.technique_lookup[technique['id']]['name']
                        self.assertEqual(expected_technique, technique['name'],
                                         f'ATT&CK technique mapping error for rule: {self.rule_str(rule)}\n'
                                         f'expected: {expected_technique} for {technique["id"]}\n'
                                         f'actual: {technique["name"]}')

                        technique_reference_id = technique['reference'].rstrip('/').split('/')[-1]
                        self.assertEqual(technique['id'], technique_reference_id,
                                         f'ATT&CK technique mapping error for rule: {self.rule_str(rule)}\n'
                                         f'technique ID {technique["id"]} does not match the reference URL ID '
                                         f'{technique["reference"]}')

                        # sub-techniques
                        sub_techniques = technique.get('subtechnique')
                        if sub_techniques:
                            for sub_technique in sub_techniques:
                                expected_sub_technique = attack.technique_lookup[sub_technique['id']]['name']
                                self.assertEqual(expected_sub_technique, sub_technique['name'],
                                                 f'ATT&CK sub-technique mapping error for rule: {self.rule_str(rule)}\n'
                                                 f'expected: {expected_sub_technique} for {sub_technique["id"]}\n'
                                                 f'actual: {sub_technique["name"]}')

                                sub_technique_reference_id = '.'.join(
                                    sub_technique['reference'].rstrip('/').split('/')[-2:])
                                self.assertEqual(sub_technique['id'], sub_technique_reference_id,
                                                 f'ATT&CK sub-technique mapping error for rule: {self.rule_str(rule)}\n'
                                                 f'sub-technique ID {sub_technique["id"]} does not match the reference URL ID '  # noqa: E501
                                                 f'{sub_technique["reference"]}')

    def test_duplicated_tactics(self):
        """Check that a tactic is only defined once."""
        for rule in self.rules:
            threat_mapping = rule.contents.get('threat', [])
            tactics = [t['tactic']['name'] for t in threat_mapping]
            duplicates = sorted(set(t for t in tactics if tactics.count(t) > 1))

            if duplicates:
                self.fail(f'{self.rule_str(rule)} duplicate tactics defined for {duplicates}. '
                          f'Flatten to a single entry per tactic')


class TestRuleTags(BaseRuleTest):
    """Test tags data for rules."""

    def test_casing_and_spacing(self):
        """Ensure consistent and expected casing for controlled tags."""
        def normalize(s):
            return ''.join(s.lower().split())

        expected_tags = [
            'APM', 'AWS', 'Asset Visibility', 'Azure', 'Configuration Audit', 'Continuous Monitoring',
            'Data Protection', 'Elastic', 'Elastic Endgame', 'Endpoint Security', 'GCP', 'Identity and Access', 'Linux',
            'Logging', 'ML', 'macOS', 'Monitoring', 'Network', 'Okta', 'Packetbeat', 'Post-Execution', 'SecOps',
            'Windows'
        ]
        expected_case = {normalize(t): t for t in expected_tags}

        for rule in self.rules:
            rule_tags = rule.contents.get('tags')
            if rule_tags:
                invalid_tags = {t: expected_case[normalize(t)] for t in rule_tags
                                if normalize(t) in list(expected_case) and t != expected_case[normalize(t)]}

                if invalid_tags:
                    error_msg = f'{self.rule_str(rule)} Invalid casing for expected tags\n'
                    error_msg += f'Actual tags: {", ".join(invalid_tags)}\n'
                    error_msg += f'Expected tags: {", ".join(invalid_tags.values())}'
                    self.fail(error_msg)

    def test_required_tags(self):
        """Test that expected tags are present within rules."""
        # indexes considered; only those with obvious relationships included
        # 'apm-*-transaction*', 'auditbeat-*', 'endgame-*', 'filebeat-*', 'logs-*', 'logs-aws*',
        # 'logs-endpoint.alerts-*', 'logs-endpoint.events.*', 'logs-okta*', 'packetbeat-*', 'winlogbeat-*'

        required_tags_map = {
            'apm-*-transaction*': {'all': ['APM']},
            'auditbeat-*': {'any': ['Windows', 'macOS', 'Linux']},
            'endgame-*': {'all': ['Elastic Endgame']},
            'logs-aws*': {'all': ['AWS']},
            'logs-endpoint.alerts-*': {'all': ['Endpoint Security']},
            'logs-endpoint.events.*': {'any': ['Windows', 'macOS', 'Linux', 'Host']},
            'logs-okta*': {'all': ['Okta']},
            'logs-windows.*': {'all': ['Windows']},
            'packetbeat-*': {'all': ['Network']},
            'winlogbeat-*': {'all': ['Windows']}
        }

        for rule in self.rules:
            rule_tags = rule.contents.get('tags', [])
            indexes = rule.contents.get('index', [])
            error_msg = f'{self.rule_str(rule)} Missing tags:\nActual tags: {", ".join(rule_tags)}'

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

    def test_primary_tactic_as_tag(self):
        from detection_rules.attack import tactics

        invalid = []
        tactics = set(tactics)

        for rule in self.rules:
            rule_tags = rule.contents['tags']

            if 'Continuous Monitoring' in rule_tags or rule.type == 'machine_learning':
                continue

            threat = rule.contents.get('threat')
            if threat:
                missing = []
                threat_tactic_names = [e['tactic']['name'] for e in threat]
                primary_tactic = threat_tactic_names[0]

                if 'Threat Detection' not in rule_tags:
                    missing.append('Threat Detection')

                # missing primary tactic
                if primary_tactic not in rule.contents['tags']:
                    missing.append(primary_tactic)

                # listed tactic that is not in threat mapping
                tag_tactics = set(rule_tags).intersection(tactics)
                missing_from_threat = list(tag_tactics.difference(threat_tactic_names))

                if missing or missing_from_threat:
                    err_msg = self.rule_str(rule)
                    if missing:
                        err_msg += f'\n    expected: {missing}'
                    if missing_from_threat:
                        err_msg += f'\n    unexpected (or missing from threat mapping): {missing_from_threat}'

                    invalid.append(err_msg)

        if invalid:
            err_msg = '\n'.join(invalid)
            self.fail(f'Rules with misaligned tags and tactics:\n{err_msg}')


class TestRuleTimelines(BaseRuleTest):
    """Test timelines in rules are valid."""

    TITLES = {
        'db366523-f1c6-4c1f-8731-6ce5ed9e5717': 'Generic Endpoint Timeline',
        '91832785-286d-4ebe-b884-1a208d111a70': 'Generic Network Timeline',
        '76e52245-7519-4251-91ab-262fb1a1728c': 'Generic Process Timeline'
    }

    def test_timeline_has_title(self):
        """Ensure rules with timelines have a corresponding title."""
        for rule in self.rules:
            timeline_id = rule.contents.get('timeline_id')
            timeline_title = rule.contents.get('timeline_title')

            if (timeline_title or timeline_id) and not (timeline_title and timeline_id):
                missing_err = f'{self.rule_str(rule)} timeline "title" and "id" required when timelines are defined'
                self.fail(missing_err)

            if timeline_id:
                unknown_id = f'{self.rule_str(rule)} Unknown timeline_id: {timeline_id}.'
                unknown_id += f' replace with {", ".join(self.TITLES)} or update this unit test with acceptable ids'
                self.assertIn(timeline_id, list(self.TITLES), unknown_id)

                unknown_title = f'{self.rule_str(rule)} unknown timeline_title: {timeline_title}'
                unknown_title += f' replace with {", ".join(self.TITLES.values())}'
                unknown_title += ' or update this unit test with acceptable titles'
                self.assertEqual(timeline_title, self.TITLES[timeline_id], )


class TestRuleFiles(BaseRuleTest):
    """Test the expected file names."""

    def test_rule_file_names_by_tactic(self):
        """Test to ensure rule files have the primary tactic prepended to the filename."""
        bad_name_rules = []

        for rule in self.rules:
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


class TestRuleMetadata(BaseRuleTest):
    """Test the metadata of rules."""

    def test_ecs_and_beats_opt_in_not_latest_only(self):
        """Test that explicitly defined opt-in validation is not only the latest versions to avoid stale tests."""
        for rule in self.rules:
            beats_version = rule.metadata.get('beats_version')
            ecs_versions = rule.metadata.get('ecs_versions', [])
            latest_beats = str(beats.get_max_version())
            latest_ecs = ecs.get_max_version()

            error_msg = f'{self.rule_str(rule)} it is unnecessary to define the current latest beats version: ' \
                        f'{latest_beats}'
            self.assertNotEqual(latest_beats, beats_version, error_msg)

            if len(ecs_versions) == 1:
                error_msg = f'{self.rule_str(rule)} it is unnecessary to define the current latest ecs version if ' \
                            f'only one version is specified: {latest_ecs}'
                self.assertNotIn(latest_ecs, ecs_versions, error_msg)

    def test_updated_date_newer_than_creation(self):
        """Test that the updated_date is newer than the creation date."""
        invalid = []

        for rule in self.rules:
            created = tuple(rule.metadata['creation_date'].split('/'))
            updated = tuple(rule.metadata['updated_date'].split('/'))
            if updated < created:
                invalid.append(rule)

        if invalid:
            rules_str = '\n '.join(self.rule_str(r, trailer=None) for r in invalid)
            err_msg = f'The following rules have an updated_date older than the creation_date\n {rules_str}'
            self.fail(err_msg)

    def test_deprecated_rules(self):
        """Test that deprecated rules are properly handled."""
        versions = load_versions()
        deprecations = load_etc_dump('deprecated_rules.json')
        deprecated_rules = {}

        for rule in self.rules:
            maturity = rule.metadata['maturity']

            if maturity == 'deprecated':
                deprecated_rules[rule.id] = rule
                err_msg = f'{self.rule_str(rule)} cannot be deprecated if it has not been version locked. ' \
                          f'Convert to `development` or delete the rule file instead'
                self.assertIn(rule.id, versions, err_msg)

                rule_path = Path(rule.path).relative_to(get_path('rules'))
                err_msg = f'{self.rule_str(rule)} deprecated rules should be stored in ' \
                          f'"{get_path("rules", "_deprecated")}" folder'
                self.assertEqual('_deprecated', rule_path.parts[0], err_msg)

                err_msg = f'{self.rule_str(rule)} missing deprecation date'
                self.assertIn('deprecation_date', rule.metadata, err_msg)

                err_msg = f'{self.rule_str(rule)} deprecation_date and updated_date should match'
                self.assertEqual(rule.metadata['deprecation_date'], rule.metadata['updated_date'], err_msg)

        missing_rules = sorted(set(versions).difference(set(self.rule_lookup)))
        missing_rule_strings = '\n '.join(f'{r} - {versions[r]["rule_name"]}' for r in missing_rules)
        err_msg = f'Deprecated rules should not be removed, but moved to the rules/_deprecated folder instead. ' \
                  f'The following rules have been version locked and are missing. ' \
                  f'Re-add to the deprecated folder and update maturity to "deprecated": \n {missing_rule_strings}'
        self.assertEqual([], missing_rules, err_msg)

        for rule_id, entry in deprecations.items():
            rule_str = f'{rule_id} - {entry["rule_name"]} ->'
            self.assertIn(rule_id, deprecated_rules, f'{rule_str} is logged in "deprecated_rules.json" but is missing')


class TestTuleTiming(BaseRuleTest):
    """Test rule timing and timestamps."""

    def test_event_override(self):
        """Test that rules have defined an timestamp_override if needed."""
        missing = []

        for rule in self.rules:
            required = False

            if 'endgame-*' in rule.contents.get('index', []):
                continue

            if rule.type == 'query':
                required = True
            elif rule.type == 'eql' and eql.utils.get_query_type(rule.parsed_query) != 'sequence':
                required = True

            if required and not rule.contents.get('timestamp_override', '') == 'event.ingested':
                missing.append(rule)

        if missing:
            rules_str = '\n '.join(self.rule_str(r, trailer=None) for r in missing)
            err_msg = f'The following rules should have the `timestamp_override` set to `event.ingested`\n {rules_str}'
            self.fail(err_msg)

    def test_required_lookback(self):
        """Ensure endpoint rules have the proper lookback time."""
        rule_types = ('query', 'eql', 'threshold')
        long_indexes = {'logs-endpoint.events.*'}
        missing = []

        for rule in self.rules:
            contents = rule.contents

            if rule.type in rule_types and set(contents.get('index', [])) & long_indexes and not contents.get('from'):
                missing.append(rule)

        if missing:
            rules_str = '\n '.join(self.rule_str(r, trailer=None) for r in missing)
            err_msg = f'The following rules should have a longer `from` defined, due to indexes used\n {rules_str}'
            self.fail(err_msg)

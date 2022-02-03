# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test that all rules have valid metadata and syntax."""
import os
import re
import warnings
from collections import defaultdict
from pathlib import Path

import eql

import kql
from detection_rules import attack
from detection_rules.version_lock import default_version_lock
from detection_rules.rule import QueryRuleData
from detection_rules.rule_loader import FILE_PATTERN
from detection_rules.schemas import definitions
from detection_rules.semver import Version
from detection_rules.utils import get_path, load_etc_dump
from rta import get_ttp_names
from .base import BaseRuleTest


class TestValidRules(BaseRuleTest):
    """Test that all detection rules load properly without duplicates."""

    def test_schema_and_dupes(self):
        """Ensure that every rule matches the schema and there are no duplicates."""
        self.assertGreaterEqual(len(self.all_rules), 1, 'No rules were loaded from rules directory!')

    def test_file_names(self):
        """Test that the file names meet the requirement."""
        file_pattern = FILE_PATTERN

        self.assertIsNone(re.match(file_pattern, 'NotValidRuleFile.toml'),
                          f'Incorrect pattern for verifying rule names: {file_pattern}')
        self.assertIsNone(re.match(file_pattern, 'still_not_a_valid_file_name.not_json'),
                          f'Incorrect pattern for verifying rule names: {file_pattern}')

        for rule in self.all_rules:
            file_name = str(rule.path.name)
            self.assertIsNotNone(re.match(file_pattern, file_name), f'Invalid file name for {rule.path}')

    def test_all_rule_queries_optimized(self):
        """Ensure that every rule query is in optimized form."""
        for rule in self.production_rules:
            if rule.contents.data.get("language") == "kql":
                source = rule.contents.data.query
                tree = kql.parse(source, optimize=False)
                optimized = tree.optimize(recursive=True)
                err_message = f'\n{self.rule_str(rule)} Query not optimized for rule\n' \
                              f'Expected: {optimized}\nActual: {source}'
                self.assertEqual(tree, optimized, err_message)

    def test_production_rules_have_rta(self):
        """Ensure that all production rules have RTAs."""
        mappings = load_etc_dump('rule-mapping.yml')
        ttp_names = get_ttp_names()

        for rule in self.production_rules:
            if isinstance(rule.contents.data, QueryRuleData) and rule.id in mappings:
                matching_rta = mappings[rule.id].get('rta_name')

                self.assertIsNotNone(matching_rta, f'{self.rule_str(rule)} does not have RTAs')

                rta_name, ext = os.path.splitext(matching_rta)
                if rta_name not in ttp_names:
                    self.fail(f'{self.rule_str(rule)} references unknown RTA: {rta_name}')

    def test_duplicate_file_names(self):
        """Test that no file names are duplicated."""
        name_map = defaultdict(list)

        for rule in self.all_rules:
            name_map[rule.path.name].append(rule.path.name)

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

        for rule in self.all_rules:
            revoked_techniques = {}
            threat_mapping = rule.contents.data.threat

            if threat_mapping:
                for entry in threat_mapping:
                    for technique in (entry.technique or []):
                        if technique.id in revoked + deprecated:
                            revoked_techniques[technique.id] = replacement_map.get(technique.id,
                                                                                   'DEPRECATED - DO NOT USE')

            if revoked_techniques:
                old_new_mapping = "\n".join(f'Actual: {k} -> Expected {v}' for k, v in revoked_techniques.items())
                self.fail(f'{self.rule_str(rule)} Using deprecated ATT&CK techniques: \n{old_new_mapping}')

    def test_tactic_to_technique_correlations(self):
        """Ensure rule threat info is properly related to a single tactic and technique."""
        for rule in self.all_rules:
            threat_mapping = rule.contents.data.threat or []
            if threat_mapping:
                for entry in threat_mapping:
                    tactic = entry.tactic
                    techniques = entry.technique or []

                    mismatched = [t.id for t in techniques if t.id not in attack.matrix[tactic.name]]
                    if mismatched:
                        self.fail(f'mismatched ATT&CK techniques for rule: {self.rule_str(rule)} '
                                  f'{", ".join(mismatched)} not under: {tactic["name"]}')

                    # tactic
                    expected_tactic = attack.tactics_map[tactic.name]
                    self.assertEqual(expected_tactic, tactic.id,
                                     f'ATT&CK tactic mapping error for rule: {self.rule_str(rule)}\n'
                                     f'expected:  {expected_tactic} for {tactic.name}\n'
                                     f'actual: {tactic.id}')

                    tactic_reference_id = tactic.reference.rstrip('/').split('/')[-1]
                    self.assertEqual(tactic.id, tactic_reference_id,
                                     f'ATT&CK tactic mapping error for rule: {self.rule_str(rule)}\n'
                                     f'tactic ID {tactic.id} does not match the reference URL ID '
                                     f'{tactic.reference}')

                    # techniques
                    for technique in techniques:
                        expected_technique = attack.technique_lookup[technique.id]['name']
                        self.assertEqual(expected_technique, technique.name,
                                         f'ATT&CK technique mapping error for rule: {self.rule_str(rule)}\n'
                                         f'expected: {expected_technique} for {technique.id}\n'
                                         f'actual: {technique.name}')

                        technique_reference_id = technique.reference.rstrip('/').split('/')[-1]
                        self.assertEqual(technique.id, technique_reference_id,
                                         f'ATT&CK technique mapping error for rule: {self.rule_str(rule)}\n'
                                         f'technique ID {technique.id} does not match the reference URL ID '
                                         f'{technique.reference}')

                        # sub-techniques
                        sub_techniques = technique.subtechnique or []
                        if sub_techniques:
                            for sub_technique in sub_techniques:
                                expected_sub_technique = attack.technique_lookup[sub_technique.id]['name']
                                self.assertEqual(expected_sub_technique, sub_technique.name,
                                                 f'ATT&CK sub-technique mapping error for rule: {self.rule_str(rule)}\n'
                                                 f'expected: {expected_sub_technique} for {sub_technique.id}\n'
                                                 f'actual: {sub_technique.name}')

                                sub_technique_reference_id = '.'.join(
                                    sub_technique.reference.rstrip('/').split('/')[-2:])
                                self.assertEqual(sub_technique.id, sub_technique_reference_id,
                                                 f'ATT&CK sub-technique mapping error for rule: {self.rule_str(rule)}\n'
                                                 f'sub-technique ID {sub_technique.id} does not match the reference URL ID '  # noqa: E501
                                                 f'{sub_technique.reference}')

    def test_duplicated_tactics(self):
        """Check that a tactic is only defined once."""
        for rule in self.all_rules:
            threat_mapping = rule.contents.data.threat
            tactics = [t.tactic.name for t in threat_mapping or []]
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

        for rule in self.all_rules:
            rule_tags = rule.contents.data.tags

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
        # 'apm-*-transaction*', 'traces-apm*', 'auditbeat-*', 'endgame-*', 'filebeat-*', 'logs-*', 'logs-aws*',
        # 'logs-endpoint.alerts-*', 'logs-endpoint.events.*', 'logs-okta*', 'packetbeat-*', 'winlogbeat-*'

        required_tags_map = {
            'apm-*-transaction*': {'all': ['APM']},
            'traces-apm*': {'all': ['APM']},
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

        for rule in self.all_rules:
            rule_tags = rule.contents.data.tags
            error_msg = f'{self.rule_str(rule)} Missing tags:\nActual tags: {", ".join(rule_tags)}'

            consolidated_optional_tags = []
            is_missing_any_tags = False
            missing_required_tags = set()

            if 'Elastic' not in rule_tags:
                missing_required_tags.add('Elastic')

            if isinstance(rule.contents.data, QueryRuleData):
                for index in rule.contents.data.index:
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

        for rule in self.all_rules:
            rule_tags = rule.contents.data.tags

            if 'Continuous Monitoring' in rule_tags or rule.contents.data.type == 'machine_learning':
                continue

            threat = rule.contents.data.threat
            if threat:
                missing = []
                threat_tactic_names = [e.tactic.name for e in threat]
                primary_tactic = threat_tactic_names[0]

                if 'Threat Detection' not in rule_tags:
                    missing.append('Threat Detection')

                # missing primary tactic
                if primary_tactic not in rule.contents.data.tags:
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

    def test_timeline_has_title(self):
        """Ensure rules with timelines have a corresponding title."""
        from detection_rules.schemas.definitions import TIMELINE_TEMPLATES

        for rule in self.all_rules:
            timeline_id = rule.contents.data.timeline_id
            timeline_title = rule.contents.data.timeline_title

            if (timeline_title or timeline_id) and not (timeline_title and timeline_id):
                missing_err = f'{self.rule_str(rule)} timeline "title" and "id" required when timelines are defined'
                self.fail(missing_err)

            if timeline_id:
                unknown_id = f'{self.rule_str(rule)} Unknown timeline_id: {timeline_id}.'
                unknown_id += f' replace with {", ".join(TIMELINE_TEMPLATES)} ' \
                              f'or update this unit test with acceptable ids'
                self.assertIn(timeline_id, list(TIMELINE_TEMPLATES), unknown_id)

                unknown_title = f'{self.rule_str(rule)} unknown timeline_title: {timeline_title}'
                unknown_title += f' replace with {", ".join(TIMELINE_TEMPLATES.values())}'
                unknown_title += ' or update this unit test with acceptable titles'
                self.assertEqual(timeline_title, TIMELINE_TEMPLATES[timeline_id], unknown_title)


class TestRuleFiles(BaseRuleTest):
    """Test the expected file names."""

    def test_rule_file_name_tactic(self):
        """Test to ensure rule files have the primary tactic prepended to the filename."""
        bad_name_rules = []

        for rule in self.all_rules:
            rule_path = rule.path.resolve()
            filename = rule_path.name

            # machine learning jobs should be in rules/ml or rules/integrations/<name>
            if rule.contents.data.type == definitions.MACHINE_LEARNING:
                continue

            threat = rule.contents.data.threat
            authors = rule.contents.data.author

            if threat and 'Elastic' in authors:
                primary_tactic = threat[0].tactic.name
                tactic_str = primary_tactic.lower().replace(' ', '_')

                if tactic_str != filename[:len(tactic_str)]:
                    bad_name_rules.append(f'{rule.id} - {Path(rule.path).name} -> expected: {tactic_str}')

        if bad_name_rules:
            error_msg = 'filename does not start with the primary tactic - update the tactic or the rule filename'
            rule_err_str = '\n'.join(bad_name_rules)
            self.fail(f'{error_msg}:\n{rule_err_str}')


class TestRuleMetadata(BaseRuleTest):
    """Test the metadata of rules."""

    def test_updated_date_newer_than_creation(self):
        """Test that the updated_date is newer than the creation date."""
        invalid = []

        for rule in self.all_rules:
            created = rule.contents.metadata.creation_date.split('/')
            updated = rule.contents.metadata.updated_date.split('/')
            if updated < created:
                invalid.append(rule)

        if invalid:
            rules_str = '\n '.join(self.rule_str(r, trailer=None) for r in invalid)
            err_msg = f'The following rules have an updated_date older than the creation_date\n {rules_str}'
            self.fail(err_msg)

    def test_deprecated_rules(self):
        """Test that deprecated rules are properly handled."""
        from detection_rules.packaging import current_stack_version

        versions = default_version_lock.version_lock
        deprecations = load_etc_dump('deprecated_rules.json')
        deprecated_rules = {}
        rules_path = get_path('rules')
        deprecated_path = get_path("rules", "_deprecated")

        misplaced_rules = [r for r in self.all_rules
                           if r.path.relative_to(rules_path).parts[-2] == '_deprecated' and  # noqa: W504
                           r.contents.metadata.maturity != 'deprecated']
        misplaced = '\n'.join(f'{self.rule_str(r)} {r.contents.metadata.maturity}' for r in misplaced_rules)
        err_str = f'The following rules are stored in {deprecated_path} but are not marked as deprecated:\n{misplaced}'
        self.assertListEqual(misplaced_rules, [], err_str)

        for rule in self.deprecated_rules:
            meta = rule.contents.metadata

            deprecated_rules[rule.id] = rule
            err_msg = f'{self.rule_str(rule)} cannot be deprecated if it has not been version locked. ' \
                      f'Convert to `development` or delete the rule file instead'
            self.assertIn(rule.id, versions, err_msg)

            rule_path = rule.path.relative_to(rules_path)
            err_msg = f'{self.rule_str(rule)} deprecated rules should be stored in ' \
                      f'"{deprecated_path}" folder'
            self.assertEqual('_deprecated', rule_path.parts[-2], err_msg)

            err_msg = f'{self.rule_str(rule)} missing deprecation date'
            self.assertIsNotNone(meta['deprecation_date'], err_msg)

            err_msg = f'{self.rule_str(rule)} deprecation_date and updated_date should match'
            self.assertEqual(meta['deprecation_date'], meta['updated_date'], err_msg)

        # skip this so the lock file can be shared across branches
        #
        # missing_rules = sorted(set(versions).difference(set(self.rule_lookup)))
        # missing_rule_strings = '\n '.join(f'{r} - {versions[r]["rule_name"]}' for r in missing_rules)
        # err_msg = f'Deprecated rules should not be removed, but moved to the rules/_deprecated folder instead. ' \
        #           f'The following rules have been version locked and are missing. ' \
        #           f'Re-add to the deprecated folder and update maturity to "deprecated": \n {missing_rule_strings}'
        # self.assertEqual([], missing_rules, err_msg)

        stack_version = Version(current_stack_version())
        for rule_id, entry in deprecations.items():
            # if a rule is deprecated and not backported in order to keep the rule active in older branches, then it
            # will exist in the deprecated_rules.json file and not be in the _deprecated folder - this is expected.
            # However, that should not occur except by exception - the proper way to handle this situation is to
            # "fork" the existing rule by adding a new min_stack_version.
            if stack_version < Version(entry['stack_version']):
                continue

            rule_str = f'{rule_id} - {entry["rule_name"]} ->'
            self.assertIn(rule_id, deprecated_rules, f'{rule_str} is logged in "deprecated_rules.json" but is missing')

    def test_integration(self):
        """Test that rules in integrations folders have matching integration defined."""
        failures = []

        for rule in self.production_rules:
            rules_path = get_path('rules')
            *_, grandparent, parent, _ = rule.path.parts
            in_integrations = grandparent == 'integrations'
            integration = rule.contents.metadata.get('integration')
            has_integration = integration is not None

            if (in_integrations or has_integration) and (parent != integration):
                err_msg = f'{self.rule_str(rule)}\nintegration: {integration}\npath: {rule.path.relative_to(rules_path)}'  # noqa: E501
                failures.append(err_msg)

        if failures:
            err_msg = 'The following rules have missing/incorrect integrations or are not in an integrations folder:\n'
            self.fail(err_msg + '\n'.join(failures))

    def test_rule_demotions(self):
        """Test to ensure a locked rule is not dropped to development, only deprecated"""
        versions = default_version_lock.version_lock
        failures = []

        for rule in self.all_rules:
            if rule.id in versions and rule.contents.metadata.maturity not in ('production', 'deprecated'):
                err_msg = f'{self.rule_str(rule)} a version locked rule can only go from production to deprecated\n'
                err_msg += f'Actual: {rule.contents.metadata.maturity}'
                failures.append(err_msg)

        if failures:
            err_msg = '\n'.join(failures)
            self.fail(f'The following rules have been improperly demoted:\n{err_msg}')

    def test_all_min_stack_rules_have_comment(self):
        failures = []

        for rule in self.all_rules:
            if rule.contents.metadata.min_stack_version and not rule.contents.metadata.min_stack_comments:
                failures.append(f'{self.rule_str(rule)} missing `metadata.min_stack_comments`. min_stack_version: '
                                f'{rule.contents.metadata.min_stack_version}')

        if failures:
            err_msg = '\n'.join(failures)
            self.fail(f'The following ({len(failures)}) rules have a `min_stack_version` defined but missing comments:'
                      f'\n{err_msg}')


class TestRuleTiming(BaseRuleTest):
    """Test rule timing and timestamps."""

    def test_event_override(self):
        """Test that rules have defined an timestamp_override if needed."""
        missing = []

        for rule in self.all_rules:
            required = False

            if isinstance(rule.contents.data, QueryRuleData) and 'endgame-*' in rule.contents.data.index:
                continue

            if rule.contents.data.type == 'query':
                required = True
            elif rule.contents.data.type == 'eql' and \
                    eql.utils.get_query_type(rule.contents.data.ast) != 'sequence':
                required = True

            if required and rule.contents.data.timestamp_override != 'event.ingested':
                missing.append(rule)

        if missing:
            rules_str = '\n '.join(self.rule_str(r, trailer=None) for r in missing)
            err_msg = f'The following rules should have the `timestamp_override` set to `event.ingested`\n {rules_str}'
            self.fail(err_msg)

    def test_required_lookback(self):
        """Ensure endpoint rules have the proper lookback time."""
        long_indexes = {'logs-endpoint.events.*'}
        missing = []

        for rule in self.all_rules:
            contents = rule.contents

            if isinstance(contents.data, QueryRuleData):
                if set(getattr(contents.data, "index", None) or []) & long_indexes and not contents.data.from_:
                    missing.append(rule)

        if missing:
            rules_str = '\n '.join(self.rule_str(r, trailer=None) for r in missing)
            err_msg = f'The following rules should have a longer `from` defined, due to indexes used\n {rules_str}'
            self.fail(err_msg)

    def test_eql_lookback(self):
        """Ensure EQL rules lookback => max_span, when defined."""
        unknowns = []
        invalids = []
        ten_minutes = 10 * 60 * 1000

        for rule in self.all_rules:
            if rule.contents.data.type == 'eql' and rule.contents.data.max_span:
                if rule.contents.data.look_back == 'unknown':
                    unknowns.append(self.rule_str(rule, trailer=None))
                else:
                    look_back = rule.contents.data.look_back
                    max_span = rule.contents.data.max_span
                    expected = look_back + ten_minutes

                    if expected < max_span:
                        invalids.append(f'{self.rule_str(rule)} lookback: {look_back}, maxspan: {max_span}, '
                                        f'expected: >={expected}')

        if unknowns:
            warn_str = '\n'.join(unknowns)
            warnings.warn(f'Unable to determine lookbacks for the following rules:\n{warn_str}')

        if invalids:
            invalids_str = '\n'.join(invalids)
            self.fail(f'The following rules have longer max_spans than lookbacks:\n{invalids_str}')

    def test_eql_interval_to_maxspan(self):
        """Check the ratio of interval to maxspan for eql rules."""
        invalids = []
        five_minutes = 5 * 60 * 1000

        for rule in self.all_rules:
            if rule.contents.data.type == 'eql':
                interval = rule.contents.data.interval or five_minutes
                maxspan = rule.contents.data.max_span
                ratio = rule.contents.data.interval_ratio

                # we want to test for at least a ratio of: interval >= 1/2 maxspan
                # but we only want to make an exception and cap the ratio at 5m interval (2.5m maxspan)
                if maxspan and maxspan > (five_minutes / 2) and ratio and ratio < .5:
                    expected = maxspan // 2
                    err_msg = f'{self.rule_str(rule)} interval: {interval}, maxspan: {maxspan}, expected: >={expected}'
                    invalids.append(err_msg)

        if invalids:
            invalids_str = '\n'.join(invalids)
            self.fail(f'The following rules have intervals too short for their given max_spans (ms):\n{invalids_str}')


class TestLicense(BaseRuleTest):
    """Test rule license."""

    def test_elastic_license_only_v2(self):
        """Test to ensure that production rules with the elastic license are only v2."""
        for rule in self.production_rules:
            rule_license = rule.contents.data.license
            if 'elastic license' in rule_license.lower():
                err_msg = f'{self.rule_str(rule)} If Elastic License is used, only v2 should be used'
                self.assertEqual(rule_license, 'Elastic License v2', err_msg)


class TestIntegrationRules(BaseRuleTest):
    """Test the note field of a rule."""

    def test_integration_guide(self):
        """Test that rules which require a config note are using standard verbiage."""
        config = '## Config\n\n'
        beats_integration_pattern = config + 'The {} Fleet integration, Filebeat module, or similarly ' \
                                             'structured data is required to be compatible with this rule.'
        render = beats_integration_pattern.format
        integration_notes = {
            'aws': render('AWS'),
            'azure': render('Azure'),
            'cyberarkpas': render('CyberArk Privileged Access Security (PAS)'),
            'gcp': render('GCP'),
            'google_workspace': render('Google Workspace'),
            'o365': render('Microsoft 365'),
            'okta': render('Okta'),
        }

        for rule in self.all_rules:
            integration = rule.contents.metadata.integration
            note_str = integration_notes.get(integration)

            if note_str:
                self.assert_(rule.contents.data.note, f'{self.rule_str(rule)} note required for config information')

                if note_str not in rule.contents.data.note:
                    self.fail(f'{self.rule_str(rule)} expected {integration} config missing\n\n'
                              f'Expected: {note_str}\n\n'
                              f'Actual: {rule.contents.data.note}')

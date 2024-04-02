# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test that all rules have valid metadata and syntax."""
import os
import re
import unittest
import uuid
import warnings
from collections import defaultdict
from pathlib import Path

import eql.ast

from marshmallow import ValidationError
from semver import Version

import kql
from detection_rules import attack
from detection_rules.integrations import (find_latest_compatible_version,
                                          load_integrations_manifests,
                                          load_integrations_schemas)
from detection_rules.misc import load_current_package_version
from detection_rules.packaging import current_stack_version
from detection_rules.rule import (AlertSuppressionMapping, QueryRuleData, QueryValidator,
                                  ThresholdAlertSuppression, TOMLRuleContents)
from detection_rules.rule_loader import FILE_PATTERN
from detection_rules.rule_validators import EQLValidator, KQLValidator
from detection_rules.schemas import definitions, get_stack_schemas
from detection_rules.utils import INTEGRATION_RULE_DIR, PatchedTemplate, get_path, load_etc_dump
from detection_rules.version_lock import default_version_lock
from rta import get_available_tests

from .base import BaseRuleTest

PACKAGE_STACK_VERSION = Version.parse(current_stack_version(), optional_minor_and_patch=True)


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
            if (
                rule.contents.data.get("language") == "kuery" and not any(
                    item in rule.contents.data.query for item in definitions.QUERY_FIELD_OP_EXCEPTIONS
                )
            ):
                source = rule.contents.data.query
                tree = kql.parse(source, optimize=False)
                optimized = tree.optimize(recursive=True)
                err_message = f'\n{self.rule_str(rule)} Query not optimized for rule\n' \
                              f'Expected: {optimized}\nActual: {source}'
                self.assertEqual(tree, optimized, err_message)

    def test_production_rules_have_rta(self):
        """Ensure that all production rules have RTAs."""
        mappings = load_etc_dump('rule-mapping.yml')
        ttp_names = sorted(get_available_tests())

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
            self.fail(f"Found duplicated file names: {duplicates}")

    def test_rule_type_changes(self):
        """Test that a rule type did not change for a locked version"""
        default_version_lock.manage_versions(self.production_rules)

    def test_bbr_validation(self):
        base_fields = {
            "author": ["Elastic"],
            "description": "test description",
            "index": ["filebeat-*", "logs-aws*"],
            "language": "kuery",
            "license": "Elastic License v2",
            "name": "test rule",
            "risk_score": 21,
            "rule_id": str(uuid.uuid4()),
            "severity": "low",
            "type": "query",
            "timestamp_override": "event.ingested"
        }

        def build_rule(query, bbr_type="default", from_field="now-120m", interval="60m"):
            metadata = {
                "creation_date": "1970/01/01",
                "updated_date": "1970/01/01",
                "min_stack_version": load_current_package_version(),
                "integration": ["cloud_defend"]
            }
            data = base_fields.copy()
            data["query"] = query
            data["building_block_type"] = bbr_type
            if from_field:
                data["from"] = from_field
            if interval:
                data["interval"] = interval
            obj = {"metadata": metadata, "rule": data}
            return TOMLRuleContents.from_dict(obj)

        query = """
            event.dataset:aws.cloudtrail and event.outcome:success
        """

        build_rule(query=query)

        with self.assertRaises(ValidationError):
            build_rule(query=query, bbr_type="invalid")

        with self.assertRaises(ValidationError):
            build_rule(query=query, from_field="now-10m", interval="10m")


class TestThreatMappings(BaseRuleTest):
    """Test threat mapping data for rules."""

    def test_technique_deprecations(self):
        """Check for use of any ATT&CK techniques that have been deprecated."""
        replacement_map = attack.load_techniques_redirect()
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


@unittest.skipIf(os.environ.get('DR_BYPASS_TAGS_VALIDATION') is not None, "Skipping tag validation")
class TestRuleTags(BaseRuleTest):
    """Test tags data for rules."""

    def test_casing_and_spacing(self):
        """Ensure consistent and expected casing for controlled tags."""

        expected_case = {t.casefold(): t for t in definitions.EXPECTED_RULE_TAGS}

        for rule in self.all_rules:
            rule_tags = rule.contents.data.tags

            if rule_tags:
                invalid_tags = {t: expected_case[t.casefold()] for t in rule_tags
                                if t.casefold() in list(expected_case) and t != expected_case[t.casefold()]}

                if invalid_tags:
                    error_msg = f'{self.rule_str(rule)} Invalid casing for expected tags\n'
                    error_msg += f'Actual tags: {", ".join(invalid_tags)}\n'
                    error_msg += f'Expected tags: {", ".join(invalid_tags.values())}'
                    self.fail(error_msg)

    def test_required_tags(self):
        """Test that expected tags are present within rules."""

        required_tags_map = {
            'logs-endpoint.events.*': {'all': ['Domain: Endpoint', 'Data Source: Elastic Defend']},
            'endgame-*': {'all': ['Data Source: Elastic Endgame']},
            'logs-aws*': {'all': ['Data Source: AWS', 'Data Source: Amazon Web Services', 'Domain: Cloud']},
            'logs-azure*': {'all': ['Data Source: Azure', 'Domain: Cloud']},
            'logs-o365*': {'all': ['Data Source: Microsoft 365', 'Domain: Cloud']},
            'logs-okta*': {'all': ['Data Source: Okta']},
            'logs-gcp*': {'all': ['Data Source: Google Cloud Platform', 'Data Source: GCP', 'Domain: Cloud']},
            'logs-google_workspace*': {'all': ['Data Source: Google Workspace', 'Domain: Cloud']},
            'logs-cloud_defend.alerts-*': {'all': ['Data Source: Elastic Defend for Containers', 'Domain: Container']},
            'logs-cloud_defend*': {'all': ['Data Source: Elastic Defend for Containers', 'Domain: Container']},
            'logs-kubernetes.*': {'all': ['Data Source: Kubernetes']},
            'apm-*-transaction*': {'all': ['Data Source: APM']},
            'traces-apm*': {'all': ['Data Source: APM']},
            '.alerts-security.*': {'all': ['Rule Type: Higher-Order Rule']},
            'logs-cyberarkpas.audit*': {'all': ['Data Source: CyberArk PAS']},
            'logs-endpoint.alerts-*': {'all': ['Data Source: Elastic Defend']},
            'logs-windows.sysmon_operational-*': {'all': ['Data Source: Sysmon']},
            'logs-windows.powershell*': {'all': ['Data Source: PowerShell Logs']},
        }

        for rule in self.all_rules:
            rule_tags = rule.contents.data.tags
            error_msg = f'{self.rule_str(rule)} Missing tags:\nActual tags: {", ".join(rule_tags)}'

            consolidated_optional_tags = []
            is_missing_any_tags = False
            missing_required_tags = set()

            if isinstance(rule.contents.data, QueryRuleData):
                for index in rule.contents.data.get('index') or []:
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
        """Test that the primary tactic is present as a tag."""
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
                primary_tactic = f"Tactic: {threat_tactic_names[0]}"

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

    def test_os_tags(self):
        """Test that OS tags are present within rules."""
        required_tags_map = {
            'linux': 'OS: Linux',
            'macos': 'OS: macOS',
            'windows': 'OS: Windows'
        }
        invalid = []
        for rule in self.all_rules:
            dir_name = rule.path.parent.name
            # if directory name is linux, macos, or windows,
            # ensure the rule has the corresponding tag
            if dir_name in ['linux', 'macos', 'windows']:
                if required_tags_map[dir_name] not in rule.contents.data.tags:
                    err_msg = self.rule_str(rule)
                    err_msg += f'\n    expected: {required_tags_map[dir_name]}'
                    invalid.append(err_msg)

        if invalid:
            err_msg = '\n'.join(invalid)
            self.fail(f'Rules with missing OS tags:\n{err_msg}')

    def test_ml_rule_type_tags(self):
        """Test that ML rule type tags are present within rules."""
        invalid = []

        for rule in self.all_rules:
            rule_tags = rule.contents.data.tags

            if rule.contents.data.type == 'machine_learning':
                if 'Rule Type: Machine Learning' not in rule_tags:
                    err_msg = self.rule_str(rule)
                    err_msg += '\n    expected: Rule Type: Machine Learning'
                    invalid.append(err_msg)
                if 'Rule Type: ML' not in rule_tags:
                    err_msg = self.rule_str(rule)
                    err_msg += '\n    expected: Rule Type: ML'
                    invalid.append(err_msg)

        if invalid:
            err_msg = '\n'.join(invalid)
            self.fail(f'Rules with misaligned ML rule type tags:\n{err_msg}')

    @unittest.skip("Skipping until all Investigation Guides follow the proper format.")
    def test_investigation_guide_tag(self):
        """Test that investigation guide tags are present within rules."""
        invalid = []
        for rule in self.all_rules:
            note = rule.contents.data.get('note')
            if note is not None:
                results = re.search(r'Investigating', note, re.M)
                if results is not None:
                    # check if investigation guide tag is present
                    if 'Resources: Investigation Guide' not in rule.contents.data.tags:
                        err_msg = self.rule_str(rule)
                        err_msg += '\n    expected: Resources: Investigation Guide'
                        invalid.append(err_msg)
        if invalid:
            err_msg = '\n'.join(invalid)
            self.fail(f'Rules with missing Investigation tag:\n{err_msg}')

    def test_tag_prefix(self):
        """Ensure all tags have a prefix from an expected list."""
        invalid = []

        for rule in self.all_rules:
            rule_tags = rule.contents.data.tags
            expected_prefixes = set([tag.split(":")[0] + ":" for tag in definitions.EXPECTED_RULE_TAGS])
            [invalid.append(f"{self.rule_str(rule)}-{tag}") for tag in rule_tags
             if not any(prefix in tag for prefix in expected_prefixes)]
        if invalid:
            self.fail(f'Rules with invalid tags:\n{invalid}')

    def test_no_duplicate_tags(self):
        """Ensure no rules have duplicate tags."""
        invalid = []

        for rule in self.all_rules:
            rule_tags = rule.contents.data.tags
            if len(rule_tags) != len(set(rule_tags)):
                invalid.append(self.rule_str(rule))

        if invalid:
            self.fail(f'Rules with duplicate tags:\n{invalid}')


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

    def test_bbr_in_correct_dir(self):
        """Ensure that BBR are in the correct directory."""
        for rule in self.bbr:
            # Is the rule a BBR
            self.assertEqual(rule.contents.data.building_block_type, 'default',
                             f'{self.rule_str(rule)} should have building_block_type = "default"')

            # Is the rule in the rules_building_block directory
            self.assertEqual(rule.path.parent.name, 'rules_building_block',
                             f'{self.rule_str(rule)} should be in the rules_building_block directory')

    def test_non_bbr_in_correct_dir(self):
        """Ensure that non-BBR are not in BBR directory."""
        proper_directory = 'rules_building_block'
        for rule in self.all_rules:
            if rule.path.parent.name == 'rules_building_block':
                self.assertIn(rule, self.bbr, f'{self.rule_str(rule)} should be in the {proper_directory}')
            else:
                # Is the rule of type BBR and not in the correct directory
                self.assertEqual(rule.contents.data.building_block_type, None,
                                 f'{self.rule_str(rule)} should be in {proper_directory}')


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
        versions = default_version_lock.version_lock
        deprecations = load_etc_dump('deprecated_rules.json')
        deprecated_rules = {}
        rules_path = get_path('rules')
        deprecated_path = get_path("rules", "_deprecated")

        misplaced_rules = []
        for r in self.all_rules:
            if "rules_building_block" in str(r.path):
                if r.contents.metadata.maturity == "deprecated":
                    misplaced_rules.append(r)
            elif r.path.relative_to(rules_path).parts[-2] == "_deprecated" \
                    and r.contents.metadata.maturity != "deprecated":
                misplaced_rules.append(r)

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

        for rule_id, entry in deprecations.items():
            # if a rule is deprecated and not backported in order to keep the rule active in older branches, then it
            # will exist in the deprecated_rules.json file and not be in the _deprecated folder - this is expected.
            # However, that should not occur except by exception - the proper way to handle this situation is to
            # "fork" the existing rule by adding a new min_stack_version.
            if PACKAGE_STACK_VERSION < Version.parse(entry['stack_version'], optional_minor_and_patch=True):
                continue

            rule_str = f'{rule_id} - {entry["rule_name"]} ->'
            self.assertIn(rule_id, deprecated_rules, f'{rule_str} is logged in "deprecated_rules.json" but is missing')

    @unittest.skipIf(PACKAGE_STACK_VERSION < Version.parse("8.3.0"),
                     "Test only applicable to 8.3+ stacks regarding related integrations build time field.")
    def test_integration_tag(self):
        """Test integration rules defined by metadata tag."""
        failures = []
        non_dataset_packages = definitions.NON_DATASET_PACKAGES + ["winlog"]

        packages_manifest = load_integrations_manifests()
        valid_integration_folders = [p.name for p in list(Path(INTEGRATION_RULE_DIR).glob("*")) if p.name != 'endpoint']

        for rule in self.production_rules:
            # TODO: temp bypass for esql rules; once parsed, we should be able to look for indexes via `FROM`
            if not rule.contents.data.get('index'):
                continue
            if isinstance(rule.contents.data, QueryRuleData) and rule.contents.data.language != 'lucene':
                rule_integrations = rule.contents.metadata.get('integration') or []
                rule_integrations = [rule_integrations] if isinstance(rule_integrations, str) else rule_integrations
                rule_promotion = rule.contents.metadata.get('promotion')
                data = rule.contents.data
                meta = rule.contents.metadata
                package_integrations = TOMLRuleContents.get_packaged_integrations(data, meta, packages_manifest)
                package_integrations_list = list(set([integration["package"] for integration in package_integrations]))
                indices = data.get('index') or []
                for rule_integration in rule_integrations:
                    if ("even.dataset" in rule.contents.data.query and not package_integrations and  # noqa: W504
                       not rule_promotion and rule_integration not in definitions.NON_DATASET_PACKAGES):  # noqa: W504
                        err_msg = f'{self.rule_str(rule)} {rule_integration} tag, but integration not \
                                found in manifests/schemas.'
                        failures.append(err_msg)

                    # checks if the rule path matches the intended integration
                    # excludes BBR rules
                    if rule_integration in valid_integration_folders and \
                            not hasattr(rule.contents.data, 'building_block_type'):
                        if rule.path.parent.name not in rule_integrations:
                            err_msg = f'{self.rule_str(rule)} {rule_integration} tag, path is {rule.path.parent.name}'
                            failures.append(err_msg)

                    # checks if an index pattern exists if the package integration tag exists
                    integration_string = "|".join(indices)
                    if not re.search(rule_integration, integration_string):
                        if rule_integration == "windows" and re.search("winlog", integration_string) or \
                                any(ri in [*map(str.lower, definitions.MACHINE_LEARNING_PACKAGES)]
                                    for ri in rule_integrations):
                            continue
                        err_msg = f'{self.rule_str(rule)} {rule_integration} tag, index pattern missing.'
                        failures.append(err_msg)

                # checks if event.dataset exists in query object and a tag exists in metadata
                # checks if metadata tag matches from a list of integrations in EPR
                if package_integrations and sorted(rule_integrations) != sorted(package_integrations_list):
                    err_msg = f'{self.rule_str(rule)} integration tags: {rule_integrations} != ' \
                              f'package integrations: {package_integrations_list}'
                    failures.append(err_msg)
                else:
                    # checks if rule has index pattern integration and the integration tag exists
                    # ignore the External Alerts rule, Threat Indicator Matching Rules, Guided onboarding
                    ignore_ids = [
                        "eb079c62-4481-4d6e-9643-3ca499df7aaa",
                        "699e9fdb-b77c-4c01-995c-1c15019b9c43",
                        "0c9a14d9-d65d-486f-9b5b-91e4e6b22bd0",
                        "a198fbbd-9413-45ec-a269-47ae4ccf59ce",
                        "0c41e478-5263-4c69-8f9e-7dfd2c22da64",
                        "aab184d3-72b3-4639-b242-6597c99d8bca",
                        "a61809f3-fb5b-465c-8bff-23a8a068ac60",
                        "f3e22c8b-ea47-45d1-b502-b57b6de950b3"
                    ]
                    if any([re.search("|".join(non_dataset_packages), i, re.IGNORECASE)
                            for i in rule.contents.data.get('index') or []]):
                        if not rule.contents.metadata.integration and rule.id not in ignore_ids and \
                                rule.contents.data.type not in definitions.MACHINE_LEARNING:
                            err_msg = f'substrings {non_dataset_packages} found in '\
                                      f'{self.rule_str(rule)} rule index patterns are {rule.contents.data.index},' \
                                      f'but no integration tag found'
                            failures.append(err_msg)

        if failures:
            err_msg = """
                The following rules have missing or invalid integrations tags.
                Try updating the integrations manifest file:
                    - `python -m detection_rules dev integrations build-manifests`\n
                """
            self.fail(err_msg + '\n'.join(failures))

    def test_invalid_queries(self):
        invalid_queries_eql = [
            """file where file.fake: (
                "token","assig", "pssc", "keystore", "pub", "pgp.asc", "ps1xml", "pem", "gpg.sig", "der", "key",
                "p7r", "p12", "asc", "jks", "p7b", "signature", "gpg", "pgp.sig", "sst", "pgp", "gpgz", "pfx", "crt",
                "p8", "sig", "pkcs7", "jceks", "pkcs8", "psc1", "p7c", "csr", "cer", "spc", "ps2xml")
            """
        ]
        invalid_integration_queries_eql = [
            """file where event.dataset == "google_workspace.drive" and event.action : ("copy", "view", "download") and
                    google_workspace.drive.fake: "people_with_link" and source.user.email == "" and
                    file.extension: (
                        "token","assig", "pssc", "keystore", "pub", "pgp.asc", "ps1xml", "pem", "gpg.sig", "der", "key",
                        "p7r", "p12", "asc", "jks", "p7b", "signature", "gpg", "pgp.sig", "sst", "pgp", "gpgz", "pfx",
                        "crt", "p8", "sig", "pkcs7", "jceks", "pkcs8", "psc1", "p7c", "csr", "cer", "spc", "ps2xml")
            """,
            """file where event.dataset == "google_workspace.drive" and event.action : ("copy", "view", "download") and
                    google_workspace.drive.visibility: "people_with_link" and source.user.email == "" and
                    file.fake: (
                        "token","assig", "pssc", "keystore", "pub", "pgp.asc", "ps1xml", "pem", "gpg.sig", "der", "key",
                        "p7r", "p12", "asc", "jks", "p7b", "signature", "gpg", "pgp.sig", "sst", "pgp", "gpgz",
                        "pfx", "crt", "p8", "sig", "pkcs7", "jceks", "pkcs8", "psc1", "p7c", "csr", "cer", "spc",
                        "ps2xml")
            """
        ]

        valid_queries_eql = [
            """file where file.extension: (
                "token","assig", "pssc", "keystore", "pub", "pgp.asc", "ps1xml", "pem",
                "p7r", "p12", "asc", "jks", "p7b", "signature", "gpg", "pgp.sig", "sst",
                "p8", "sig", "pkcs7", "jceks", "pkcs8", "psc1", "p7c", "csr", "cer")
            """,
            """file where event.dataset == "google_workspace.drive" and event.action : ("copy", "view", "download") and
                    google_workspace.drive.visibility: "people_with_link" and source.user.email == "" and
                    file.extension: (
                        "token","assig", "pssc", "keystore", "pub", "pgp.asc", "ps1xml", "pem", "gpg.sig", "der", "key",
                        "p7r", "p12", "asc", "jks", "p7b", "signature", "gpg", "pgp.sig", "sst", "pgp", "gpgz", "pfx",
                        "p8", "sig", "pkcs7", "jceks", "pkcs8", "psc1", "p7c", "csr", "cer", "spc", "ps2xml")
            """

        ]

        invalid_queries_kql = [
            """
            event.fake:"google_workspace.admin" and event.action:"CREATE_DATA_TRANSFER_REQUEST"
              and event.category:"iam" and google_workspace.admin.application.name:Drive*
            """
        ]
        invalid_integration_queries_kql = [
            """
            event.dataset:"google_workspace.admin" and event.action:"CREATE_DATA_TRANSFER_REQUEST"
              and event.category:"iam" and google_workspace.fake:Drive*
            """
        ]

        valid_queries_kql = [
            """
            event.dataset:"google_workspace.admin" and event.action:"CREATE_DATA_TRANSFER_REQUEST"
              and event.category:"iam" and google_workspace.admin.application.name:Drive*
            """,
            """
            event.dataset:"google_workspace.admin" and event.action:"CREATE_DATA_TRANSFER_REQUEST"
            """

        ]

        base_fields_eql = {
            "author": ["Elastic"],
            "description": "test description",
            "index": ["filebeat-*"],
            "language": "eql",
            "license": "Elastic License v2",
            "name": "test rule",
            "risk_score": 21,
            "rule_id": str(uuid.uuid4()),
            "severity": "low",
            "type": "eql"
        }

        base_fields_kql = {
            "author": ["Elastic"],
            "description": "test description",
            "index": ["filebeat-*"],
            "language": "kuery",
            "license": "Elastic License v2",
            "name": "test rule",
            "risk_score": 21,
            "rule_id": str(uuid.uuid4()),
            "severity": "low",
            "type": "query"
        }

        def build_rule(query: str, query_language: str):
            metadata = {
                "creation_date": "1970/01/01",
                "integration": ["google_workspace"],
                "updated_date": "1970/01/01",
                "query_schema_validation": True,
                "maturity": "production",
                "min_stack_version": load_current_package_version()
            }
            if query_language == "eql":
                data = base_fields_eql.copy()
            elif query_language == "kuery":
                data = base_fields_kql.copy()
            data["query"] = query
            obj = {"metadata": metadata, "rule": data}
            return TOMLRuleContents.from_dict(obj)
        # eql
        for query in valid_queries_eql:
            build_rule(query, "eql")

        for query in invalid_queries_eql:
            with self.assertRaises(eql.EqlSchemaError):
                build_rule(query, "eql")

        for query in invalid_integration_queries_eql:
            with self.assertRaises(ValueError):
                build_rule(query, "eql")
        # kql
        for query in valid_queries_kql:
            build_rule(query, "kuery")

        for query in invalid_queries_kql:
            with self.assertRaises(kql.KqlParseError):
                build_rule(query, "kuery")

        for query in invalid_integration_queries_kql:
            with self.assertRaises(ValueError):
                build_rule(query, "kuery")

    def test_event_dataset(self):
        for rule in self.all_rules:
            if isinstance(rule.contents.data, QueryRuleData):
                # Need to pick validator based on language
                if rule.contents.data.language == "kuery":
                    test_validator = KQLValidator(rule.contents.data.query)
                elif rule.contents.data.language == "eql":
                    test_validator = EQLValidator(rule.contents.data.query)
                else:
                    continue
                data = rule.contents.data
                meta = rule.contents.metadata
                if meta.query_schema_validation is not False or meta.maturity != "deprecated":
                    if isinstance(data, QueryRuleData) and data.language != 'lucene':
                        packages_manifest = load_integrations_manifests()
                        pkg_integrations = TOMLRuleContents.get_packaged_integrations(data, meta, packages_manifest)

                        validation_integrations_check = None

                        if pkg_integrations:
                            # validate the query against related integration fields
                            validation_integrations_check = test_validator.validate_integration(data,
                                                                                                meta,
                                                                                                pkg_integrations)

                        if validation_integrations_check and "event.dataset" in rule.contents.data.query:
                            raise validation_integrations_check


class TestIntegrationRules(BaseRuleTest):
    """Test integration rules."""

    @unittest.skip("8.3+ Stacks Have Related Integrations Feature")
    def test_integration_guide(self):
        """Test that rules which require a config note are using standard verbiage."""
        config = '## Setup\n\n'
        beats_integration_pattern = config + 'The {} Fleet integration, Filebeat module, or similarly ' \
                                             'structured data is required to be compatible with this rule.'
        render = beats_integration_pattern.format
        integration_notes = {
            'aws': render('AWS'),
            'azure': render('Azure'),
            'cyberarkpas': render('CyberArk Privileged Access Security (PAS)'),
            'gcp': render('GCP'),
            'google_workspace': render('Google Workspace'),
            'o365': render('Office 365 Logs'),
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

    def test_ml_integration_jobs_exist(self):
        """Test that machine learning jobs exist in the integration."""
        failures = []

        ml_integration_names = list(map(str.lower, definitions.MACHINE_LEARNING_PACKAGES))
        integration_schemas = load_integrations_schemas()
        integration_manifests = load_integrations_manifests()

        for rule in self.all_rules:
            if rule.contents.data.type == "machine_learning":
                ml_integration_name = next((i for i in rule.contents.metadata.integration
                                            if i in ml_integration_names), None)
                if ml_integration_name:
                    if "machine_learning_job_id" not in dir(rule.contents.data):
                        failures.append(f'{self.rule_str(rule)} missing `machine_learning_job_id`')
                    else:
                        rule_job_id = rule.contents.data.machine_learning_job_id
                        ml_schema = integration_schemas.get(ml_integration_name)
                        min_version = Version.parse(
                            rule.contents.metadata.min_stack_version or load_current_package_version(),
                            optional_minor_and_patch=True
                        )
                        latest_compat_ver = find_latest_compatible_version(
                            package=ml_integration_name,
                            integration="",
                            rule_stack_version=min_version,
                            packages_manifest=integration_manifests
                        )
                        compat_integration_schema = ml_schema[latest_compat_ver[0]]
                        if rule_job_id not in compat_integration_schema['jobs']:
                            failures.append(
                                f'{self.rule_str(rule)} machine_learning_job_id `{rule_job_id}` not found '
                                f'in version `{latest_compat_ver[0]}` of `{ml_integration_name}` integration. '
                                f'existing jobs: {compat_integration_schema["jobs"]}'
                            )

        if failures:
            err_msg = '\n'.join(failures)
            self.fail(
                f'The following ({len(failures)}) rules are missing a valid `machine_learning_job_id`:\n{err_msg}'
            )


class TestRuleTiming(BaseRuleTest):
    """Test rule timing and timestamps."""

    def test_event_override(self):
        """Test that timestamp_override is properly applied to rules."""
        # kql: always require (fallback to @timestamp enabled)
        # eql:
        #   sequences: never
        #   min_stack_version >= 8.2: any - fallback to @timestamp enabled https://github.com/elastic/kibana/pull/127989
        #  if 'event.ingested' is missing, '@timestamp' will be default
        errors = []

        for rule in self.all_rules:
            # skip rules that do not leverage queries (i.e. machine learning)
            # filters to acceptable query languages in definitions.FilterLanguages
            # QueryRuleData should inheritenly ignore machine learning rules
            if isinstance(rule.contents.data, QueryRuleData):
                rule_language = rule.contents.data.language
                has_event_ingested = rule.contents.data.get('timestamp_override') == 'event.ingested'
                rule_str = self.rule_str(rule, trailer=None)

                if not has_event_ingested:
                    # TODO: determine if we expand this to ES|QL
                    # ignores any rule that does not use EQL or KQL queries specifically
                    # this does not avoid rule types where variants of KQL are used (e.g. new terms)
                    if rule_language not in ('eql', 'kuery') or rule.contents.data.is_sequence:
                        continue
                    else:
                        errors.append(f'{rule_str} - rule must have `timestamp_override: event.ingested`')

        if errors:
            self.fail('The following rules are invalid:\n' + '\n'.join(errors))

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


class TestIncompatibleFields(BaseRuleTest):
    """Test stack restricted fields do not backport beyond allowable limits."""

    def test_rule_backports_for_restricted_fields(self):
        """Test that stack restricted fields will not backport to older rule versions."""
        invalid_rules = []

        for rule in self.all_rules:
            invalid = rule.contents.check_restricted_fields_compatibility()
            if invalid:
                invalid_rules.append(f'{self.rule_str(rule)} {invalid}')

        if invalid_rules:
            invalid_str = '\n'.join(invalid_rules)
            err_msg = 'The following rules have min_stack_versions lower than allowed for restricted fields:\n'
            err_msg += invalid_str
            self.fail(err_msg)


class TestBuildTimeFields(BaseRuleTest):
    """Test validity of build-time fields."""

    def test_build_fields_min_stack(self):
        """Test that newly introduced build-time fields for a min_stack for applicable rules."""
        current_stack_ver = PACKAGE_STACK_VERSION
        invalids = []

        for rule in self.production_rules:
            min_stack = rule.contents.metadata.min_stack_version
            build_fields = rule.contents.data.get_build_fields()

            errors = []
            for build_field, field_versions in build_fields.items():
                start_ver, end_ver = field_versions
                if start_ver is not None and current_stack_ver >= start_ver:
                    if min_stack is None or not Version.parse(min_stack) >= start_ver:
                        errors.append(f'{build_field} >= {start_ver}')

            if errors:
                err_str = ', '.join(errors)
                invalids.append(f'{self.rule_str(rule)} uses a rule type with build fields requiring min_stack_versions'
                                f' to be set: {err_str}')

            if invalids:
                self.fail(invalids)


class TestRiskScoreMismatch(BaseRuleTest):
    """Test that severity and risk_score fields contain corresponding values"""

    def test_rule_risk_score_severity_mismatch(self):
        invalid_list = []
        risk_severity = {
            "critical": (74, 100),  # updated range for critical
            "high": (48, 73),       # updated range for high
            "medium": (22, 47),     # updated range for medium
            "low": (0, 21),         # updated range for low
        }
        for rule in self.all_rules:
            severity = rule.contents.data.severity
            risk_score = rule.contents.data.risk_score

            # Check if the risk_score falls within the range for the severity level
            min_score, max_score = risk_severity[severity]
            if not min_score <= risk_score <= max_score:
                invalid_list.append(f'{self.rule_str(rule)} Severity: {severity}, Risk Score: {risk_score}')

        if invalid_list:
            invalid_str = '\n'.join(invalid_list)
            err_msg = 'The following rules have mismatches between Severity and Risk Score field values:\n'
            err_msg += invalid_str
            self.fail(err_msg)


class TestNoteMarkdownPlugins(BaseRuleTest):
    """Test if a guide containing Osquery Plugin syntax contains the version note."""

    def test_note_has_osquery_warning(self):
        """Test that all rules with osquery entries have the default notification of stack compatibility."""
        osquery_note_pattern = ('> **Note**:\n> This investigation guide uses the [Osquery Markdown Plugin]'
                                '(https://www.elastic.co/guide/en/security/master/invest-guide-run-osquery.html) '
                                'introduced in Elastic Stack version 8.5.0. Older Elastic Stack versions will display '
                                'unrendered Markdown in this guide.')
        invest_note_pattern = ('> This investigation guide uses the [Investigate Markdown Plugin]'
                               '(https://www.elastic.co/guide/en/security/master/interactive-investigation-guides.html)'
                               ' introduced in Elastic Stack version 8.8.0. Older Elastic Stack versions will display '
                               'unrendered Markdown in this guide.')

        for rule in self.production_rules.rules:
            if not rule.contents.get('transform'):
                continue

            osquery = rule.contents.transform.get('osquery')
            if osquery and osquery_note_pattern not in rule.contents.data.note:
                self.fail(f'{self.rule_str(rule)} Investigation guides using the Osquery Markdown must contain '
                          f'the following note:\n{osquery_note_pattern}')

            investigate = rule.contents.transform.get('investigate')
            if investigate and invest_note_pattern not in rule.contents.data.note:
                self.fail(f'{self.rule_str(rule)} Investigation guides using the Investigate Markdown must contain '
                          f'the following note:\n{invest_note_pattern}')

    def test_plugin_placeholders_match_entries(self):
        """Test that the number of plugin entries match their respective placeholders in note."""
        for rule in self.production_rules.rules:
            has_transform = rule.contents.get('transform') is not None
            has_note = rule.contents.data.get('note') is not None
            note = rule.contents.data.note

            if has_transform:
                if not has_note:
                    self.fail(f'{self.rule_str(rule)} transformed defined with no note')
            else:
                if not has_note:
                    continue

            note_template = PatchedTemplate(note)
            identifiers = [i for i in note_template.get_identifiers() if '_' in i]

            if not has_transform:
                if identifiers:
                    self.fail(f'{self.rule_str(rule)} note contains plugin placeholders with no transform entries')
                else:
                    continue

            transform = rule.contents.transform
            transform_counts = {plugin: len(entries) for plugin, entries in transform.to_dict().items()}

            note_counts = defaultdict(int)
            for identifier in identifiers:
                # "$" is used for other things, so this verifies the pattern of a trailing "_" followed by ints
                if '_' not in identifier:
                    continue
                dash_index = identifier.rindex('_')
                if dash_index == len(identifier) or not identifier[dash_index + 1:].isdigit():
                    continue

                plugin, _ = identifier.split('_')
                if plugin in transform_counts:
                    note_counts[plugin] += 1

            err_msg = f'{self.rule_str(rule)} plugin entry count mismatch between transform and note'
            self.assertDictEqual(transform_counts, note_counts, err_msg)

    def test_if_plugins_explicitly_defined(self):
        """Check if plugins are explicitly defined with the pattern in note vs using transform."""
        for rule in self.production_rules.rules:
            note = rule.contents.data.get('note')
            if note is not None:
                results = re.search(r'(!{osquery|!{investigate)', note, re.I | re.M)
                err_msg = f'{self.rule_str(rule)} investigation guide plugin pattern detected! Use Transform'
                self.assertIsNone(results, err_msg)


class TestAlertSuppression(BaseRuleTest):
    """Test rule alert suppression."""

    @unittest.skipIf(PACKAGE_STACK_VERSION < Version.parse("8.8.0"),
                     "Test only applicable to 8.8+ stacks for rule alert suppression feature.")
    def test_group_field_in_schemas(self):
        """Test to ensure the fields are defined is in ECS/Beats/Integrations schema."""
        for rule in self.production_rules:
            rule_type = rule.contents.data.get('type')
            if rule_type in ('query', 'threshold') and rule.contents.data.get('alert_suppression'):
                if isinstance(rule.contents.data.alert_suppression, AlertSuppressionMapping):
                    group_by_fields = rule.contents.data.alert_suppression.group_by
                elif isinstance(rule.contents.data.alert_suppression, ThresholdAlertSuppression):
                    group_by_fields = rule.contents.data.threshold.field
                min_stack_version = rule.contents.metadata.get("min_stack_version")
                if min_stack_version is None:
                    min_stack_version = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
                else:
                    min_stack_version = Version.parse(min_stack_version)
                integration_tag = rule.contents.metadata.get("integration")
                ecs_version = get_stack_schemas()[str(min_stack_version)]['ecs']
                beats_version = get_stack_schemas()[str(min_stack_version)]['beats']
                queryvalidator = QueryValidator(rule.contents.data.query)
                _, _, schema = queryvalidator.get_beats_schema([], beats_version, ecs_version)
                if integration_tag:
                    # if integration tag exists in rule, append integration schema to existing schema
                    # grabs the latest
                    integration_schemas = load_integrations_schemas()
                    for ints in integration_tag:
                        integration_schema = integration_schemas[ints]
                        int_schema = integration_schema[list(integration_schema.keys())[-1]]
                        for data_source in int_schema.keys():
                            schema.update(**int_schema[data_source])
                for fld in group_by_fields:
                    if fld not in schema.keys():
                        self.fail(f"{self.rule_str(rule)} alert suppression field {fld} not \
                            found in ECS, Beats, or non-ecs schemas")

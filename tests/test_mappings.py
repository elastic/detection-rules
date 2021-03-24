# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test that all rules appropriately match against expected data sets."""
import copy
import warnings

from detection_rules.rule import KQLRuleData
from . import get_data_files, get_fp_data_files
from detection_rules import rule_loader
from detection_rules.utils import combine_sources, evaluate, load_etc_dump
from .base import BaseRuleTest


class TestMappings(BaseRuleTest):
    """Test that all rules appropriately match against expected data sets."""

    FP_FILES = get_fp_data_files()
    RULES = rule_loader.load_rules().values()

    def evaluate(self, documents, rule, expected, msg):
        """KQL engine to evaluate."""
        filtered = evaluate(rule, documents)
        self.assertEqual(expected, len(filtered), msg)
        return filtered

    def test_true_positives(self):
        """Test that expected results return against true positives."""
        mismatched_ecs = []
        mappings = load_etc_dump('rule-mapping.yml')

        for rule in self.production_rules:
            if isinstance(rule.contents.data, KQLRuleData):
                if rule.id not in mappings:
                    continue

                mapping = mappings[rule.id]
                expected = mapping['count']
                sources = mapping.get('sources')
                rta_file = mapping['rta_name']

                # ensure sources is defined and not empty; schema allows it to not be set since 'pending' bypasses
                self.assertTrue(sources, 'No sources defined for: {} - {} '.format(rule.id, rule.name))
                msg = 'Expected TP results did not match for: {} - {}'.format(rule.id, rule.name)

                data_files = [get_data_files('true_positives', rta_file).get(s) for s in sources]
                data_file = combine_sources(*data_files)
                results = self.evaluate(data_file, rule, expected, msg)

                ecs_versions = set([r.get('ecs', {}).get('version') for r in results])
                rule_ecs = set(rule.metadata.get('ecs_version').copy())

                if not ecs_versions & rule_ecs:
                    msg = '{} - {} ecs_versions ({}) not in source data versions ({})'.format(
                        rule.id, rule.name, ', '.join(rule_ecs), ', '.join(ecs_versions))
                    mismatched_ecs.append(msg)

        if mismatched_ecs:
            msg = 'Rules detected with source data from ecs versions not listed within the rule: \n{}'.format(
                '\n'.join(mismatched_ecs))
            warnings.warn(msg)

    def test_false_positives(self):
        """Test that expected results return against false positives."""
        for rule in self.production_rules:
            if isinstance(rule.contents.data, KQLRuleData):
                for fp_name, merged_data in get_fp_data_files().items():
                    msg = 'Unexpected FP match for: {} - {}, against: {}'.format(rule.id, rule.name, fp_name)
                    self.evaluate(copy.deepcopy(merged_data), rule, 0, msg)

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Shared resources for tests."""

import unittest

from detection_rules import rule_loader
from detection_rules.rule import TOMLRule
from detection_rules.rule_loader import RuleCollection, production_filter


class BaseRuleTest(unittest.TestCase):
    """Base class for shared test cases which need to load rules"""

    @classmethod
    def setUpClass(cls):
        cls.rule_files = rule_loader.load_rule_files(verbose=False)
        cls.rule_lookup = rule_loader.load_rules(verbose=False)
        cls.all_rules = RuleCollection.default()
        cls.production_rules = cls.all_rules.filter(production_filter)
        cls.production_rules = rule_loader.get_production_rules()

    @staticmethod
    def rule_str(rule: TOMLRule, trailer=' ->'):
        return f'{rule.id} - {rule.name}{trailer or ""}'

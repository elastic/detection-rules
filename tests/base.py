# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Shared resources for tests."""

import unittest

from detection_rules.rule import TOMLRule
from detection_rules.rule_loader import RuleCollection, production_filter


class BaseRuleTest(unittest.TestCase):
    """Base class for shared test cases which need to load rules"""

    @classmethod
    def setUpClass(cls):
        cls.all_rules = RuleCollection.default()
        cls.rule_lookup = {rule.id: rule for rule in cls.all_rules}
        cls.production_rules = cls.all_rules.filter(production_filter)

    @staticmethod
    def rule_str(rule: TOMLRule, trailer=' ->'):
        return f'{rule.id} - {rule.name}{trailer or ""}'

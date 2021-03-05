# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Shared resources for tests."""

import unittest

from detection_rules import rule_loader
from detection_rules.rule import Rule


class RuleLoadTest(unittest.TestCase):
    """Base class for shared test cases which need to load rules"""

    @classmethod
    def setUpClass(cls):
        cls.rule_files = rule_loader.load_rule_files(verbose=False)
        cls.rule_lookup = rule_loader.load_rules(verbose=False)
        cls.rules = cls.rule_lookup.values()
        cls.production_rules = rule_loader.get_production_rules()

    @staticmethod
    def rule_str(rule: Rule, trailer=' ->'):
        return f'{rule.id} - {rule.name}{trailer or ""}'

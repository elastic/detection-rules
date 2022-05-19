# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Shared resources for tests."""

import unittest
from typing import Union

from detection_rules.rule import TOMLRule
from detection_rules.rule_loader import DeprecatedCollection, DeprecatedRule, RuleCollection, production_filter


class BaseRuleTest(unittest.TestCase):
    """Base class for shared test cases which need to load rules"""

    @classmethod
    def setUpClass(cls):
        rc = RuleCollection.default()
        cls.all_rules = rc.rules
        cls.rule_lookup = rc.id_map
        cls.production_rules = rc.filter(production_filter)
        cls.deprecated_rules: DeprecatedCollection = rc.deprecated

    @staticmethod
    def rule_str(rule: Union[DeprecatedRule, TOMLRule], trailer=' ->'):
        return f'{rule.id} - {rule.name}{trailer or ""}'

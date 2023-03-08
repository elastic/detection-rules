# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Shared resources for tests."""

import unittest
from functools import lru_cache
from typing import Union

from detection_rules.rule import TOMLRule
from detection_rules.rule_loader import DeprecatedCollection, DeprecatedRule, RuleCollection, production_filter


RULE_LOADER_FAIL = False
RULE_LOADER_FAIL_MSG = None
RULE_LOADER_FAIL_RAISED = False


@lru_cache
def default_rules() -> RuleCollection:
    return RuleCollection.default()


class BaseRuleTest(unittest.TestCase):
    """Base class for shared test cases which need to load rules"""

    RULE_LOADER_FAIL = False
    RULE_LOADER_FAIL_MSG = None
    RULE_LOADER_FAIL_RAISED = False

    @classmethod
    def setUpClass(cls):
        global RULE_LOADER_FAIL, RULE_LOADER_FAIL_MSG

        # too noisy; refactor
        # os.environ["DR_NOTIFY_INTEGRATION_UPDATE_AVAILABLE"] = "1"

        if not RULE_LOADER_FAIL:
            try:
                rc = default_rules()
                cls.all_rules = rc.rules
                cls.rule_lookup = rc.id_map
                cls.production_rules = rc.filter(production_filter)
                cls.deprecated_rules: DeprecatedCollection = rc.deprecated
            except Exception as e:
                RULE_LOADER_FAIL = True
                RULE_LOADER_FAIL_MSG = str(e)

    @staticmethod
    def rule_str(rule: Union[DeprecatedRule, TOMLRule], trailer=' ->') -> str:
        return f'{rule.id} - {rule.name}{trailer or ""}'

    def setUp(self) -> None:
        global RULE_LOADER_FAIL, RULE_LOADER_FAIL_MSG, RULE_LOADER_FAIL_RAISED

        if RULE_LOADER_FAIL:
            # limit the loader failure to just one run
            # raise a dedicated test failure for the loader
            if not RULE_LOADER_FAIL_RAISED:
                RULE_LOADER_FAIL_RAISED = True
                with self.subTest('Test that the rule loader loaded with no validation or other failures.'):
                    self.fail(f'Rule loader failure: \n{RULE_LOADER_FAIL_MSG}')

            self.skipTest('Rule loader failure')
        else:
            super().setUp()

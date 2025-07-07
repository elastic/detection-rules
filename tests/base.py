# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Shared resources for tests."""

import os
import unittest
from functools import lru_cache
from pathlib import Path

from detection_rules.config import parse_rules_config
from detection_rules.rule import TOMLRule
from detection_rules.rule_loader import DeprecatedCollection, DeprecatedRule, RuleCollection, production_filter

RULE_LOADER_FAIL = False
RULE_LOADER_FAIL_MSG = None
RULE_LOADER_FAIL_RAISED = False

CUSTOM_RULES_DIR = os.getenv("CUSTOM_RULES_DIR", None)
RULES_CONFIG = parse_rules_config()


@lru_cache
def load_rules() -> RuleCollection:
    if CUSTOM_RULES_DIR:
        rc = RuleCollection()
        path = Path(CUSTOM_RULES_DIR)
        assert path.exists(), f"Custom rules directory {path} does not exist"
        rc.load_directories(directories=RULES_CONFIG.rule_dirs)
        rc.freeze()
        return rc
    return RuleCollection.default()


def default_bbr(rc: RuleCollection) -> RuleCollection:
    rules = [r for r in rc.rules if "rules_building_block" in r.path.parent.parts]
    return RuleCollection(rules=rules)


class BaseRuleTest(unittest.TestCase):
    """Base class for shared test cases which need to load rules"""

    RULE_LOADER_FAIL = False
    RULE_LOADER_FAIL_MSG = None
    RULE_LOADER_FAIL_RAISED = False

    @classmethod
    def setUpClass(cls):
        global RULE_LOADER_FAIL, RULE_LOADER_FAIL_MSG  # noqa: PLW0603

        if not RULE_LOADER_FAIL:
            try:
                rc = load_rules()
                rc_bbr = default_bbr(rc)
                cls.rc = rc
                cls.all_rules = rc.filter(production_filter)
                cls.bbr = rc_bbr.rules
                cls.deprecated_rules: DeprecatedCollection = rc.deprecated
            except Exception as e:  # noqa: BLE001
                RULE_LOADER_FAIL = True
                RULE_LOADER_FAIL_MSG = str(e)

        cls.custom_dir = Path(CUSTOM_RULES_DIR).resolve() if CUSTOM_RULES_DIR else None
        cls.rules_config = RULES_CONFIG

    @staticmethod
    def rule_str(rule: DeprecatedRule | TOMLRule, trailer=" ->") -> str:
        return f"{rule.id} - {rule.name}{trailer or ''}"

    def setUp(self) -> None:
        global RULE_LOADER_FAIL_RAISED  # noqa: PLW0603

        if RULE_LOADER_FAIL:
            # limit the loader failure to just one run
            # raise a dedicated test failure for the loader
            if not RULE_LOADER_FAIL_RAISED:
                RULE_LOADER_FAIL_RAISED = True
                with self.subTest("Test that the rule loader loaded with no validation or other failures."):
                    self.fail(f"Rule loader failure: {RULE_LOADER_FAIL_MSG}")

            self.skipTest("Rule loader failure")
        else:
            super().setUp()

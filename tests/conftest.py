# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Shared resources for tests."""


from functools import lru_cache
from typing import Union

import pytest

from detection_rules.rule import TOMLRule
from detection_rules.rule_loader import (
    DeprecatedCollection,
    DeprecatedRule,
    RuleCollection,
    production_filter,
)

RULE_LOADER_FAIL = False
RULE_LOADER_FAIL_MSG = None
RULE_LOADER_FAIL_RAISED = False


@lru_cache
def default_rules() -> RuleCollection:
    return RuleCollection.default()


@lru_cache
def default_bbr() -> RuleCollection:
    return RuleCollection.default_bbr()


@pytest.fixture(scope="class")
def rule_data(request):
    global RULE_LOADER_FAIL, RULE_LOADER_FAIL_MSG
    if not RULE_LOADER_FAIL:
        try:
            rc = default_rules()
            rc_bbr = default_bbr()
            request.cls.all_rules = rc.rules
            request.cls.rule_lookup = rc.id_map
            request.cls.production_rules = rc.filter(production_filter)
            request.cls.bbr = rc_bbr.rules
            request.cls.deprecated_rules: DeprecatedCollection = rc.deprecated
        except Exception as e:
            RULE_LOADER_FAIL = True
            RULE_LOADER_FAIL_MSG = str(e)


@pytest.mark.usefixtures("rule_data")
class TestBaseRule:
    """Base class for shared test cases which need to load rules"""

    RULE_LOADER_FAIL = False
    RULE_LOADER_FAIL_MSG = None
    RULE_LOADER_FAIL_RAISED = False


    @staticmethod
    def rule_str(rule: Union[DeprecatedRule, TOMLRule], trailer=' ->') -> str:
        return f'{rule.id} - {rule.name}{trailer or ""}'

    def setup_method(self, method):
        global RULE_LOADER_FAIL, RULE_LOADER_FAIL_MSG, RULE_LOADER_FAIL_RAISED
        if RULE_LOADER_FAIL:
            # limit the loader failure to just one run
            # raise a dedicated test failure for the loader
            if not RULE_LOADER_FAIL_RAISED:
                RULE_LOADER_FAIL_RAISED = True
                pytest.fail(f'Rule loader failure: \n{RULE_LOADER_FAIL_MSG}')
            pytest.skip('Rule loader failure')

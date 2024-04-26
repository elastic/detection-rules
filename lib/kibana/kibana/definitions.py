# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from typing import Literal, Union, TypedDict, NotRequired


RuleBulkActions = Literal['enable', 'disable', 'delete', 'duplicate', 'export', 'edit']


class RuleBulkAddTags(TypedDict):
    type: Literal['add_tags']
    value: list[str]


class RuleBulkDeleteTags(TypedDict):
    type: Literal['delete_tags']
    value: list[str]


class RuleBulkSetTags(TypedDict):
    type: Literal['set_tags']
    value: list[str]


class RuleBulkAddIndexPatterns(TypedDict):
    type: Literal['add_index_patterns']
    value: list[str]


class RuleBulkDeleteIndexPatterns(TypedDict):
    type: Literal['delete_index_patterns']
    value: list[str]


class RuleBulkSetIndexPatterns(TypedDict):
    type: Literal['set_index_patterns']
    value: list[str]


class _ValueSetTimeline(TypedDict):
    timeline_id: str
    timeline_title: str


class RuleBulkSetTimeline(TypedDict):
    type: Literal['set_timeline']
    value: _ValueSetTimeline


class _ValueSetSchedule(TypedDict):
    interval: str
    lookback: str


class RuleBulkSetSchedule(TypedDict):
    type: Literal['set_schedule']
    value: _ValueSetSchedule


class _ValueAddOrSetRuleActions(TypedDict):
    actions: list[dict]  # intentionally not setting based on literal values
    throttle: NotRequired[dict]  # to be deprecated


class RuleBulkAddRuleActions(TypedDict):
    type: Literal['add_rule_actions']
    value: _ValueAddOrSetRuleActions


class RuleBulkSetRuleActions(TypedDict):
    type: Literal['set_rule_actions']
    value: _ValueAddOrSetRuleActions


RuleBulkEditActionTypes = Union[
    RuleBulkAddTags,
    RuleBulkDeleteTags,
    RuleBulkSetTags,
    RuleBulkAddIndexPatterns,
    RuleBulkDeleteIndexPatterns,
    RuleBulkSetIndexPatterns,
    RuleBulkSetTimeline,
    RuleBulkSetSchedule,
    RuleBulkAddRuleActions,
    RuleBulkSetRuleActions
]

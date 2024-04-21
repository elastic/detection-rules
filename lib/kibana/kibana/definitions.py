# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from dataclasses import dataclass
from typing import Any, Dict, List, Literal, NewType, Union


RuleBulkActions = Literal['enable', 'disable', 'delete', 'duplicate', 'export', 'edit']

RuleBulkAddTags = NewType('RuleBulkAddTags', List[str])
RuleBulkDeleteTags = NewType('RuleBulkDeleteTags', List[str])
RuleBulkSetTags = NewType('RuleBulkSetTags', List[str])
RuleBulkAddIndexPatterns = NewType('RuleBulkAddIndexPatterns', List[str])
RuleBulkDeleteIndexPatterns = NewType('RuleBulkDeleteIndexPatterns', List[str])
RuleBulkSetIndexPatterns = NewType('RuleBulkSetIndexPatterns', List[str])
RuleBulkSetTimelineTitle = NewType('RuleBulkSetTimelineTitle', Dict[Literal['timeline_id', 'timeline_title'], str])
RuleBulkSetSchedule = NewType('RuleBulkSetSchedule', Dict[Literal['interval', 'lookback'], str])
RuleBulkAddRuleActions = NewType('RuleBulkAddRuleActions', Dict[Literal['actions', 'throttle'], Union[List[dict], dict]])
RuleBulkSetRuleActions = NewType('RuleBulkSetRuleActions', Dict[Literal['actions', 'throttle'], Union[List[dict], dict]])

RuleBulkEditActionTypes = Union[
    RuleBulkAddTags,
    RuleBulkDeleteTags,
    RuleBulkSetTags,
    RuleBulkAddIndexPatterns,
    RuleBulkDeleteIndexPatterns,
    RuleBulkSetIndexPatterns,
    RuleBulkSetTimelineTitle,
    RuleBulkSetSchedule,
    RuleBulkAddRuleActions,
    RuleBulkSetRuleActions
]


# @dataclass
# class RuleBulkEditAction:
#     type: RuleBulkEditActionTypes
#     value: Any


# @dataclass
# class RuleBulkDuplicateAction:
#     include_exceptions: bool

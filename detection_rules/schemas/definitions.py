# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Custom shared definitions for schemas."""

from typing import Literal, Final

from marshmallow import validate
from marshmallow_dataclass import NewType

ASSET_TYPE = "security_rule"
SAVED_OBJECT_TYPE = "security-rule"

DATE_PATTERN = r'\d{4}/\d{2}/\d{2}'
MATURITY_LEVELS = ['development', 'experimental', 'beta', 'production', 'deprecated']
OS_OPTIONS = ['windows', 'linux', 'macos']
PR_PATTERN = r'^$|\d+'
SHA256_PATTERN = r'[a-fA-F0-9]{64}'
UUID_PATTERN = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'

_version = r'\d+\.\d+(\.\d+[\w-]*)*'
CONDITION_VERSION_PATTERN = rf'^\^{_version}$'
VERSION_PATTERN = f'^{_version}$'
BRANCH_PATTERN = f'{VERSION_PATTERN}|^master$'

INTERVAL_PATTERN = r'\d+[mshd]'
TACTIC_URL = r'https://attack.mitre.org/tactics/TA[0-9]+/'
TECHNIQUE_URL = r'https://attack.mitre.org/techniques/T[0-9]+/'
SUBTECHNIQUE_URL = r'https://attack.mitre.org/techniques/T[0-9]+/[0-9]+/'
MACHINE_LEARNING = 'machine_learning'
SAVED_QUERY = 'saved_query'
QUERY = 'query'


OPERATORS = ['equals']

TIMELINE_TEMPLATES: Final[dict] = {
    'db366523-f1c6-4c1f-8731-6ce5ed9e5717': 'Generic Endpoint Timeline',
    '91832785-286d-4ebe-b884-1a208d111a70': 'Generic Network Timeline',
    '76e52245-7519-4251-91ab-262fb1a1728c': 'Generic Process Timeline',
    '495ad7a7-316e-4544-8a0f-9c098daee76e': 'Generic Threat Match Timeline'
}


BranchVer = NewType('BranchVer', str, validate=validate.Regexp(BRANCH_PATTERN))
CodeString = NewType("CodeString", str)
ConditionSemVer = NewType('ConditionSemVer', str, validate=validate.Regexp(CONDITION_VERSION_PATTERN))
Date = NewType('Date', str, validate=validate.Regexp(DATE_PATTERN))
FilterLanguages = Literal["kuery", "lucene"]
Interval = NewType('Interval', str, validate=validate.Regexp(INTERVAL_PATTERN))
PositiveInteger = NewType('PositiveInteger', int, validate=validate.Range(min=1))
Markdown = NewType("MarkdownField", CodeString)
Maturity = Literal['development', 'experimental', 'beta', 'production', 'deprecated']
MaxSignals = NewType("MaxSignals", int, validate=validate.Range(min=1))
NonEmptyStr = NewType('NonEmptyStr', str, validate=validate.Length(min=1))
Operator = Literal['equals']
OSType = Literal['windows', 'linux', 'macos']
RiskScore = NewType("MaxSignals", int, validate=validate.Range(min=1, max=100))
RuleType = Literal['query', 'saved_query', 'machine_learning', 'eql', 'threshold', 'threat_match']
SemVer = NewType('SemVer', str, validate=validate.Regexp(VERSION_PATTERN))
Severity = Literal['low', 'medium', 'high', 'critical']
Sha256 = NewType('Sha256', str, validate=validate.Regexp(SHA256_PATTERN))
SubTechniqueURL = NewType('SubTechniqueURL', str, validate=validate.Regexp(SUBTECHNIQUE_URL))
TacticURL = NewType('TacticURL', str, validate=validate.Regexp(TACTIC_URL))
TechniqueURL = NewType('TechniqueURL', str, validate=validate.Regexp(TECHNIQUE_URL))
ThresholdValue = NewType("ThresholdValue", int, validate=validate.Range(min=1))
TimelineTemplateId = NewType('TimelineTemplateId', str, validate=validate.OneOf(list(TIMELINE_TEMPLATES)))
TimelineTemplateTitle = NewType('TimelineTemplateTitle', str, validate=validate.OneOf(TIMELINE_TEMPLATES.values()))
UUIDString = NewType('UUIDString', str, validate=validate.Regexp(UUID_PATTERN))


# experimental machine learning features and releases
MachineLearningType = Literal['DGA', 'ProblemChild']
MachineLearningTypeLower = Literal['dga', 'problemchild']

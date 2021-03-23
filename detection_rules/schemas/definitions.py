# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Custom shared definitions for schemas."""

from typing import Literal

from marshmallow import validate
from marshmallow_dataclass import NewType

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


CodeString = NewType("CodeString", str)
ConditionSemVer = NewType('ConditionSemVer', str, validate=validate.Regexp(CONDITION_VERSION_PATTERN))
Date = NewType('Date', str, validate=validate.Regexp(DATE_PATTERN))
Interval = NewType('Interval', str, validate=validate.Regexp(INTERVAL_PATTERN))
MaxSignals = NewType("MaxSignals", int, validate=validate.Range(min=1))
TacticURL = NewType('TacticURL', str, validate=validate.Regexp(TACTIC_URL))
SubTechniqueURL = NewType('SubTechniqueURL', str, validate=validate.Regexp(SUBTECHNIQUE_URL))
TechniqueURL = NewType('TechniqueURL', str, validate=validate.Regexp(TECHNIQUE_URL))
Markdown = NewType("MarkdownField", CodeString)
Operator = Literal['equals']
RiskScore = NewType("MaxSignals", int, validate=validate.Range(min=1, max=100))
SemVer = NewType('SemVer', str, validate=validate.Regexp(VERSION_PATTERN))
Severity = Literal['low', 'medium', 'high', 'critical']
Sha256 = NewType('Sha256', str, validate=validate.Regexp(SHA256_PATTERN))
UUIDString = NewType('UUIDString', str, validate=validate.Regexp(UUID_PATTERN))
Maturity = Literal['development', 'experimental', 'beta', 'production', 'deprecated']
OSType = Literal['windows', 'linux', 'macos']
RuleType = Literal['query', 'saved_query', 'machine_learning', 'eql']
ThresholdValue = NewType("ThresholdValue", int, validate=validate.Range(min=1))

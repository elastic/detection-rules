# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Custom shared definitions for schemas."""

from typing import List, Literal, Final

from marshmallow import validate
from marshmallow_dataclass import NewType
from semver import Version

ASSET_TYPE = "security_rule"
SAVED_OBJECT_TYPE = "security-rule"

DATE_PATTERN = r'^\d{4}/\d{2}/\d{2}$'
MATURITY_LEVELS = ['development', 'experimental', 'beta', 'production', 'deprecated']
OS_OPTIONS = ['windows', 'linux', 'macos']
NAME_PATTERN = r'^[a-zA-Z0-9].+?[a-zA-Z0-9()]$'
PR_PATTERN = r'^$|\d+$'
SHA256_PATTERN = r'^[a-fA-F0-9]{64}$'
UUID_PATTERN = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

_version = r'\d+\.\d+(\.\d+[\w-]*)*'
CONDITION_VERSION_PATTERN = rf'^\^{_version}$'
VERSION_PATTERN = f'^{_version}$'
MINOR_SEMVER = r'^\d+\.\d+$'
BRANCH_PATTERN = f'{VERSION_PATTERN}|^master$'
ELASTICSEARCH_EQL_FEATURES = {
    "allow_negation": (Version.parse('8.9.0'), None),
    "allow_runs": (Version.parse('7.16.0'), None),
    "allow_sample": (Version.parse('8.6.0'), None),
    "elasticsearch_validate_optional_fields": (Version.parse('7.16.0'), None)
}
NON_DATASET_PACKAGES = ['apm', 'endpoint', 'system', 'windows', 'cloud_defend', 'network_traffic']
NON_PUBLIC_FIELDS = {
    "related_integrations": (Version.parse('8.3.0'), None),
    "required_fields": (Version.parse('8.3.0'), None),
    "setup": (Version.parse('8.3.0'), None)
}
INTERVAL_PATTERN = r'^\d+[mshd]$'
TACTIC_URL = r'^https://attack.mitre.org/tactics/TA[0-9]+/$'
TECHNIQUE_URL = r'^https://attack.mitre.org/techniques/T[0-9]+/$'
SUBTECHNIQUE_URL = r'^https://attack.mitre.org/techniques/T[0-9]+/[0-9]+/$'
MACHINE_LEARNING = 'machine_learning'
QUERY = 'query'
QUERY_FIELD_OP_EXCEPTIONS = ["powershell.file.script_block_text"]

# we had a bad rule ID make it in before tightening up the pattern, and so we have to let it bypass
KNOWN_BAD_RULE_IDS = Literal['119c8877-8613-416d-a98a-96b6664ee73a5']
KNOWN_BAD_DEPRECATED_DATES = Literal['2021-03-03']
OPERATORS = ['equals']

TIMELINE_TEMPLATES: Final[dict] = {
    'db366523-f1c6-4c1f-8731-6ce5ed9e5717': 'Generic Endpoint Timeline',
    '91832785-286d-4ebe-b884-1a208d111a70': 'Generic Network Timeline',
    '76e52245-7519-4251-91ab-262fb1a1728c': 'Generic Process Timeline',
    '495ad7a7-316e-4544-8a0f-9c098daee76e': 'Generic Threat Match Timeline',
    '4d4c0b59-ea83-483f-b8c1-8c360ee53c5c': 'Comprehensive File Timeline',
    'e70679c2-6cde-4510-9764-4823df18f7db': 'Comprehensive Process Timeline',
    '300afc76-072d-4261-864d-4149714bf3f1': 'Comprehensive Network Timeline',
    '3e47ef71-ebfc-4520-975c-cb27fc090799': 'Comprehensive Registry Timeline',
    '3e827bab-838a-469f-bd1e-5e19a2bff2fd': 'Alerts Involving a Single User Timeline',
    '4434b91a-94ca-4a89-83cb-a37cdc0532b7': 'Alerts Involving a Single Host Timeline'
}

EXPECTED_RULE_TAGS = [
    'Data Source: Active Directory',
    'Data Source: Amazon Web Services',
    'Data Source: AWS',
    'Data Source: APM',
    'Data Source: Azure',
    'Data Source: CyberArk PAS',
    'Data Source: Elastic Defend',
    'Data Source: Elastic Defend for Containers',
    'Data Source: Elastic Endgame',
    'Data Source: GCP',
    'Data Source: Google Cloud Platform',
    'Data Source: Google Workspace',
    'Data Source: Kubernetes',
    'Data Source: Microsoft 365',
    'Data Source: Okta',
    'Data Source: PowerShell Logs',
    'Data Source: Sysmon Only',
    'Data Source: Zoom',
    'Domain: Cloud',
    'Domain: Container',
    'Domain: Endpoint',
    'OS: Linux',
    'OS: macOS',
    'OS: Windows',
    'Rule Type: BBR',
    'Resources: Investigation Guide',
    'Rule Type: Higher-Order Rule',
    'Rule Type: Machine Learning',
    'Rule Type: ML',
    'Tactic: Collection',
    'Tactic: Command and Control',
    'Tactic: Credential Access',
    'Tactic: Defense Evasion',
    'Tactic: Discovery',
    'Tactic: Execution',
    'Tactic: Exfiltration',
    'Tactic: Impact',
    'Tactic: Initial Access',
    'Tactic: Lateral Movement',
    'Tactic: Persistence',
    'Tactic: Privilege Escalation',
    'Tactic: Reconnaissance',
    'Tactic: Resource Development',
    'Threat: BPFDoor',
    'Threat: Cobalt Strike',
    'Threat: Lightning Framework',
    'Threat: Orbit',
    'Threat: Rootkit',
    'Threat: TripleCross',
    'Use Case: Active Directory Monitoring',
    'Use Case: Asset Visibility',
    'Use Case: Configuration Audit',
    'Use Case: Guided Onboarding',
    'Use Case: Identity and Access Audit',
    'Use Case: Log Auditing',
    'Use Case: Network Security Monitoring',
    'Use Case: Threat Detection',
    'Use Case: UEBA',
    'Use Case: Vulnerability'
]

MACHINE_LEARNING_PACKAGES = ['LMD', 'DGA', 'DED', 'ProblemChild', 'Beaconing']

AlertSuppressionMissing = NewType('AlertSuppressionMissing', str,
                                  validate=validate.OneOf(['suppress', 'doNotSuppress']))
NonEmptyStr = NewType('NonEmptyStr', str, validate=validate.Length(min=1))
TimeUnits = Literal['s', 'm', 'h']
BranchVer = NewType('BranchVer', str, validate=validate.Regexp(BRANCH_PATTERN))
CardinalityFields = NewType('CardinalityFields', List[NonEmptyStr], validate=validate.Length(min=0, max=3))
CodeString = NewType("CodeString", str)
ConditionSemVer = NewType('ConditionSemVer', str, validate=validate.Regexp(CONDITION_VERSION_PATTERN))
Date = NewType('Date', str, validate=validate.Regexp(DATE_PATTERN))
FilterLanguages = Literal["eql", "esql", "kuery", "lucene"]
Interval = NewType('Interval', str, validate=validate.Regexp(INTERVAL_PATTERN))
InvestigateProviderQueryType = Literal["phrase", "range"]
InvestigateProviderValueType = Literal["string", "boolean"]
Markdown = NewType("MarkdownField", CodeString)
Maturity = Literal['development', 'experimental', 'beta', 'production', 'deprecated']
MaxSignals = NewType("MaxSignals", int, validate=validate.Range(min=1))
NewTermsFields = NewType('NewTermsFields', List[NonEmptyStr], validate=validate.Length(min=1, max=3))
Operator = Literal['equals']
OSType = Literal['windows', 'linux', 'macos']
PositiveInteger = NewType('PositiveInteger', int, validate=validate.Range(min=1))
RiskScore = NewType("MaxSignals", int, validate=validate.Range(min=1, max=100))
RuleName = NewType('RuleName', str, validate=validate.Regexp(NAME_PATTERN))
RuleType = Literal['query', 'saved_query', 'machine_learning', 'eql', 'esql', 'threshold', 'threat_match', 'new_terms']
SemVer = NewType('SemVer', str, validate=validate.Regexp(VERSION_PATTERN))
SemVerMinorOnly = NewType('SemVerFullStrict', str, validate=validate.Regexp(MINOR_SEMVER))
Severity = Literal['low', 'medium', 'high', 'critical']
Sha256 = NewType('Sha256', str, validate=validate.Regexp(SHA256_PATTERN))
SubTechniqueURL = NewType('SubTechniqueURL', str, validate=validate.Regexp(SUBTECHNIQUE_URL))
TacticURL = NewType('TacticURL', str, validate=validate.Regexp(TACTIC_URL))
TechniqueURL = NewType('TechniqueURL', str, validate=validate.Regexp(TECHNIQUE_URL))
ThresholdValue = NewType("ThresholdValue", int, validate=validate.Range(min=1))
TimelineTemplateId = NewType('TimelineTemplateId', str, validate=validate.OneOf(list(TIMELINE_TEMPLATES)))
TimelineTemplateTitle = NewType('TimelineTemplateTitle', str, validate=validate.OneOf(TIMELINE_TEMPLATES.values()))
TransformTypes = Literal["osquery", "investigate"]
UUIDString = NewType('UUIDString', str, validate=validate.Regexp(UUID_PATTERN))
BuildingBlockType = Literal['default']

# experimental machine learning features and releases
MachineLearningType = getattr(Literal, '__getitem__')(tuple(MACHINE_LEARNING_PACKAGES))  # noqa: E999
MachineLearningTypeLower = getattr(Literal, '__getitem__')(
    tuple(map(str.lower, MACHINE_LEARNING_PACKAGES)))  # noqa: E999

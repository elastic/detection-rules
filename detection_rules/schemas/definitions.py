# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Custom shared definitions for schemas."""
import os
from typing import Final, List, Literal

from marshmallow import fields, validate
from marshmallow_dataclass import NewType
from semver import Version

from detection_rules.config import CUSTOM_RULES_DIR


def elastic_timeline_template_id_validator():
    """Custom validator for Timeline Template IDs."""
    def validator(value):
        if os.environ.get('DR_BYPASS_TIMELINE_TEMPLATE_VALIDATION') is not None:
            fields.String().deserialize(value)
        else:
            validate.OneOf(list(TIMELINE_TEMPLATES))(value)

    return validator


def elastic_timeline_template_title_validator():
    """Custom validator for Timeline Template Titles."""
    def validator(value):
        if os.environ.get('DR_BYPASS_TIMELINE_TEMPLATE_VALIDATION') is not None:
            fields.String().deserialize(value)
        else:
            validate.OneOf(TIMELINE_TEMPLATES.values())(value)

    return validator


def elastic_rule_name_regexp(pattern):
    """Custom validator for rule names."""
    def validator(value):
        if not CUSTOM_RULES_DIR:
            validate.Regexp(pattern)(value)
        else:
            fields.String().deserialize(value)
    return validator


ASSET_TYPE = "security_rule"
SAVED_OBJECT_TYPE = "security-rule"

DATE_PATTERN = r'^\d{4}/\d{2}/\d{2}$'
MATURITY_LEVELS = ['development', 'experimental', 'beta', 'production', 'deprecated']
OS_OPTIONS = ['windows', 'linux', 'macos']
NAME_PATTERN = r'^[a-zA-Z0-9].+?[a-zA-Z0-9\[\]()]$'
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
NON_DATASET_PACKAGES = ['apm',
                        'auditd_manager',
                        'cloud_defend',
                        'endpoint',
                        'jamf_protect',
                        'network_traffic',
                        'system',
                        'windows',
                        'sentinel_one_cloud_funnel',
                        'ti_rapid7_threat_command',
                        'm365_defender',
                        'panw']
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
# Known Null values that cannot be handled in TOML due to lack of Null value support via compound dicts
KNOWN_NULL_ENTRIES = [{"rule.actions": "frequency.throttle"}]
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
    'Data Source: Auditd Manager',
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
    'Mitre Atlas: *',
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
NonEmptyStr = NewType('NonEmptyStr', str, validate=validate.Length(min=1))
MACHINE_LEARNING_PACKAGES = ['LMD', 'DGA', 'DED', 'ProblemChild', 'Beaconing']
AlertSuppressionGroupBy = NewType('AlertSuppressionGroupBy', List[NonEmptyStr], validate=validate.Length(min=1, max=3))
AlertSuppressionMissing = NewType('AlertSuppressionMissing', str,
                                  validate=validate.OneOf(['suppress', 'doNotSuppress']))
AlertSuppressionValue = NewType("AlertSupressionValue", int, validate=validate.Range(min=1))
TimeUnits = Literal['s', 'm', 'h']
BranchVer = NewType('BranchVer', str, validate=validate.Regexp(BRANCH_PATTERN))
CardinalityFields = NewType('CardinalityFields', List[NonEmptyStr], validate=validate.Length(min=0, max=3))
CodeString = NewType("CodeString", str)
ConditionSemVer = NewType('ConditionSemVer', str, validate=validate.Regexp(CONDITION_VERSION_PATTERN))
Date = NewType('Date', str, validate=validate.Regexp(DATE_PATTERN))
ExceptionEntryOperator = Literal['included', 'excluded']
ExceptionEntryType = Literal['match', 'match_any', 'exists', 'list', 'wildcard', 'nested']
ExceptionNamespaceType = Literal['single', 'agnostic']
ExceptionItemEndpointTags = Literal['endpoint', 'os:windows', 'os:linux', 'os:macos']
ExceptionContainerType = Literal['detection', 'endpoint', 'rule_default']
ExceptionItemType = Literal['simple']
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
RuleName = NewType('RuleName', str, validate=elastic_rule_name_regexp(NAME_PATTERN))
RuleType = Literal['query', 'saved_query', 'machine_learning', 'eql', 'esql', 'threshold', 'threat_match', 'new_terms']
SemVer = NewType('SemVer', str, validate=validate.Regexp(VERSION_PATTERN))
SemVerMinorOnly = NewType('SemVerFullStrict', str, validate=validate.Regexp(MINOR_SEMVER))
Severity = Literal['low', 'medium', 'high', 'critical']
Sha256 = NewType('Sha256', str, validate=validate.Regexp(SHA256_PATTERN))
SubTechniqueURL = NewType('SubTechniqueURL', str, validate=validate.Regexp(SUBTECHNIQUE_URL))
StoreType = Literal['appState', 'globalState']
TacticURL = NewType('TacticURL', str, validate=validate.Regexp(TACTIC_URL))
TechniqueURL = NewType('TechniqueURL', str, validate=validate.Regexp(TECHNIQUE_URL))
ThresholdValue = NewType("ThresholdValue", int, validate=validate.Range(min=1))
TimelineTemplateId = NewType('TimelineTemplateId', str, validate=elastic_timeline_template_id_validator())
TimelineTemplateTitle = NewType('TimelineTemplateTitle', str, validate=elastic_timeline_template_title_validator())
TransformTypes = Literal["osquery", "investigate"]
UUIDString = NewType('UUIDString', str, validate=validate.Regexp(UUID_PATTERN))
BuildingBlockType = Literal['default']

# experimental machine learning features and releases
MachineLearningType = getattr(Literal, '__getitem__')(tuple(MACHINE_LEARNING_PACKAGES))  # noqa: E999
MachineLearningTypeLower = getattr(Literal, '__getitem__')(
    tuple(map(str.lower, MACHINE_LEARNING_PACKAGES)))  # noqa: E999
##

ActionTypeId = Literal[
    ".slack", ".slack_api", ".email", ".index", ".pagerduty", ".swimlane", ".webhook", ".servicenow",
    ".servicenow-itom", ".servicenow-sir", ".jira", ".resilient", ".opsgenie", ".teams", ".torq", ".tines",
    ".d3security"
]
EsDataTypes = Literal[
    'binary', 'boolean',
    'keyword', 'constant_keyword', 'wildcard',
    'long', 'integer', 'short', 'byte', 'double', 'float', 'half_float', 'scaled_float', 'unsigned_long',
    'date', 'date_nanos',
    'alias', 'object', 'flatten', 'nested', 'join',
    'integer_range', 'float_range', 'long_range', 'double_range', 'date_range', 'ip_range',
    'ip', 'version', 'murmur3', 'aggregate_metric_double', 'histogram',
    'text', 'text_match_only', 'annotated-text', 'completion', 'search_as_you_type', 'token_count',
    'dense_vector', 'sparse_vector', 'rank_feature', 'rank_features',
    'geo_point', 'geo_shape', 'point', 'shape',
    'percolator'
]

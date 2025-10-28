# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Custom shared definitions for schemas."""

import os
import re
from collections.abc import Callable
from re import Pattern
from typing import Annotated, Any, Final, Literal, NewType

from marshmallow import fields, validate
from semver import Version

from detection_rules.config import CUSTOM_RULES_DIR


def elastic_timeline_template_id_validator() -> Callable[[Any], Any]:
    """Custom validator for Timeline Template IDs."""

    def validator_wrapper(value: Any) -> Any:
        if os.environ.get("DR_BYPASS_TIMELINE_TEMPLATE_VALIDATION") is None:
            template_ids = list(TIMELINE_TEMPLATES)
            validator = validate.OneOf(template_ids)
            validator(value)
        return value

    return validator_wrapper


def elastic_timeline_template_title_validator() -> Callable[[Any], Any]:
    """Custom validator for Timeline Template Titles."""

    def validator_wrapper(value: Any) -> Any:
        if os.environ.get("DR_BYPASS_TIMELINE_TEMPLATE_VALIDATION") is None:
            template_titles = TIMELINE_TEMPLATES.values()
            validator = validate.OneOf(template_titles)
            validator(value)
        return value

    return validator_wrapper


def elastic_rule_name_regexp(pattern: Pattern[str]) -> Callable[[Any], Any]:
    """Custom validator for rule names."""

    regexp_validator = validate.Regexp(pattern)

    def validator_wrapper(value: Any) -> Any:
        if not CUSTOM_RULES_DIR:
            regexp_validator(value)
        return value

    return validator_wrapper


HTTP_STATUS_BAD_REQUEST = 400
ASSET_TYPE = "security_rule"
SAVED_OBJECT_TYPE = "security-rule"

DATE_PATTERN = re.compile(r"^\d{4}/\d{2}/\d{2}$")
MATURITY_LEVELS = ["development", "experimental", "beta", "production", "deprecated"]
OS_OPTIONS = ["windows", "linux", "macos"]

NAME_PATTERN = re.compile(r"^[a-zA-Z0-9].+?[a-zA-Z0-9\[\]()]$")
PR_PATTERN = re.compile(r"^$|\d+$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
# NOTE this additional bad UUID pattern is a stop gap until the rule has been deprecated
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"  # UUID pattern
    r"|^7eb54028-ca72-4eb7-8185-b6864572347db$"  # Additional pattern of known bad UUID
)
_version = r"\d+\.\d+(\.\d+[\w-]*)*"
CONDITION_VERSION_PATTERN = re.compile(rf"^\^{_version}$")
VERSION_PATTERN = f"^{_version}$"
MINOR_SEMVER = re.compile(r"^\d+\.\d+$")
FROM_SOURCES_REGEX = re.compile(r"^\s*FROM\s+(?P<sources>.+?)\s*(?:\||\bmetadata\b|//|$)", re.IGNORECASE | re.MULTILINE)
BRANCH_PATTERN = f"{VERSION_PATTERN}|^master$"
ELASTICSEARCH_EQL_FEATURES = {
    "allow_negation": (Version.parse("8.9.0"), None),
    "allow_runs": (Version.parse("7.16.0"), None),
    "allow_sample": (Version.parse("8.6.0"), None),
    "elasticsearch_validate_optional_fields": (Version.parse("7.16.0"), None),
}
NON_DATASET_PACKAGES = [
    "apm",
    "auditd_manager",
    "cloud_defend",
    "endpoint",
    "jamf_protect",
    "network_traffic",
    "system",
    "windows",
    "sentinel_one_cloud_funnel",
    "ti_rapid7_threat_command",
    "m365_defender",
    "panw",
    "crowdstrike",
]
NON_PUBLIC_FIELDS = {
    "related_integrations": (Version.parse("8.3.0"), None),
    "required_fields": (Version.parse("8.3.0"), None),
    "setup": (Version.parse("8.3.0"), None),
}
INTERVAL_PATTERN = r"^\d+[mshd]$"
TACTIC_URL = r"^https://attack.mitre.org/tactics/TA[0-9]+/$"
TECHNIQUE_URL = r"^https://attack.mitre.org/techniques/T[0-9]+/$"
SUBTECHNIQUE_URL = r"^https://attack.mitre.org/techniques/T[0-9]+/[0-9]+/$"
MACHINE_LEARNING = "machine_learning"
QUERY = "query"
QUERY_FIELD_OP_EXCEPTIONS = ["powershell.file.script_block_text"]

# we had a bad rule ID make it in before tightening up the pattern, and so we have to let it bypass
KNOWN_BAD_RULE_IDS = Literal["119c8877-8613-416d-a98a-96b6664ee73a5", "7eb54028-ca72-4eb7-8185-b6864572347db"]
KNOWN_BAD_DEPRECATED_DATES = Literal["2021-03-03"]
# Known Null values that cannot be handled in TOML due to lack of Null value support via compound dicts
KNOWN_NULL_ENTRIES = [{"rule.actions": "frequency.throttle"}]
OPERATORS = ["equals"]

TIMELINE_TEMPLATES: Final[dict[str, str]] = {
    "db366523-f1c6-4c1f-8731-6ce5ed9e5717": "Generic Endpoint Timeline",
    "91832785-286d-4ebe-b884-1a208d111a70": "Generic Network Timeline",
    "76e52245-7519-4251-91ab-262fb1a1728c": "Generic Process Timeline",
    "495ad7a7-316e-4544-8a0f-9c098daee76e": "Generic Threat Match Timeline",
    "4d4c0b59-ea83-483f-b8c1-8c360ee53c5c": "Comprehensive File Timeline",
    "e70679c2-6cde-4510-9764-4823df18f7db": "Comprehensive Process Timeline",
    "300afc76-072d-4261-864d-4149714bf3f1": "Comprehensive Network Timeline",
    "3e47ef71-ebfc-4520-975c-cb27fc090799": "Comprehensive Registry Timeline",
    "3e827bab-838a-469f-bd1e-5e19a2bff2fd": "Alerts Involving a Single User Timeline",
    "4434b91a-94ca-4a89-83cb-a37cdc0532b7": "Alerts Involving a Single Host Timeline",
}

EXPECTED_RULE_TAGS = [
    "Data Source: Active Directory",
    "Data Source: Amazon Web Services",
    "Data Source: Auditd Manager",
    "Data Source: AWS",
    "Data Source: APM",
    "Data Source: Azure",
    "Data Source: CyberArk PAS",
    "Data Source: Elastic Defend",
    "Data Source: Elastic Defend for Containers",
    "Data Source: Elastic Endgame",
    "Data Source: GCP",
    "Data Source: Google Cloud Platform",
    "Data Source: Google Workspace",
    "Data Source: Kubernetes",
    "Data Source: Microsoft 365",
    "Data Source: Okta",
    "Data Source: PowerShell Logs",
    "Data Source: Sysmon Only",
    "Data Source: Zoom",
    "Domain: Cloud",
    "Domain: Container",
    "Domain: Endpoint",
    "Mitre Atlas: *",
    "OS: Linux",
    "OS: macOS",
    "OS: Windows",
    "Promotion: External Alerts",
    "Rule Type: BBR",
    "Resources: Investigation Guide",
    "Rule Type: Higher-Order Rule",
    "Rule Type: Machine Learning",
    "Rule Type: ML",
    "Tactic: Collection",
    "Tactic: Command and Control",
    "Tactic: Credential Access",
    "Tactic: Defense Evasion",
    "Tactic: Discovery",
    "Tactic: Execution",
    "Tactic: Exfiltration",
    "Tactic: Impact",
    "Tactic: Initial Access",
    "Tactic: Lateral Movement",
    "Tactic: Persistence",
    "Tactic: Privilege Escalation",
    "Tactic: Reconnaissance",
    "Tactic: Resource Development",
    "Threat: BPFDoor",
    "Threat: Cobalt Strike",
    "Threat: Lightning Framework",
    "Threat: Orbit",
    "Threat: Rootkit",
    "Threat: TripleCross",
    "Use Case: Active Directory Monitoring",
    "Use Case: Asset Visibility",
    "Use Case: Configuration Audit",
    "Use Case: Guided Onboarding",
    "Use Case: Identity and Access Audit",
    "Use Case: Log Auditing",
    "Use Case: Network Security Monitoring",
    "Use Case: Threat Detection",
    "Use Case: UEBA",
    "Use Case: Vulnerability",
]

MACHINE_LEARNING_PACKAGES = ["LMD", "DGA", "DED", "ProblemChild", "Beaconing", "PAD"]

CodeString = NewType("CodeString", str)
Markdown = NewType("Markdown", CodeString)

TimeUnits = Literal["s", "m", "h"]
ExceptionEntryOperator = Literal["included", "excluded"]
ExceptionEntryType = Literal["match", "match_any", "exists", "list", "wildcard", "nested"]
ExceptionNamespaceType = Literal["single", "agnostic"]
ExceptionItemEndpointTags = Literal["endpoint", "os:windows", "os:linux", "os:macos"]
ExceptionContainerType = Literal["detection", "endpoint", "rule_default"]
ExceptionItemType = Literal["simple"]
FilterLanguages = Literal["eql", "esql", "kuery", "lucene"]

InvestigateProviderQueryType = Literal["phrase", "range"]
InvestigateProviderValueType = Literal["string", "boolean"]

Operator = Literal["equals"]
OSType = Literal["windows", "linux", "macos"]

Severity = Literal["low", "medium", "high", "critical"]
Maturity = Literal["development", "experimental", "beta", "production", "deprecated"]
RuleType = Literal["query", "saved_query", "machine_learning", "eql", "esql", "threshold", "threat_match", "new_terms"]
StoreType = Literal["appState", "globalState"]
TransformTypes = Literal["osquery", "investigate"]
BuildingBlockType = Literal["default"]

NON_EMPTY_STRING_FIELD = fields.String(validate=validate.Length(min=1))
NonEmptyStr = Annotated[str, NON_EMPTY_STRING_FIELD]

AlertSuppressionGroupBy = Annotated[
    list[NonEmptyStr], fields.List(NON_EMPTY_STRING_FIELD, validate=validate.Length(min=1, max=3))
]
AlertSuppressionMissing = Annotated[str, fields.String(validate=validate.OneOf(["suppress", "doNotSuppress"]))]
AlertSuppressionValue = Annotated[int, fields.Integer(validate=validate.Range(min=1))]
BranchVer = Annotated[str, fields.String(validate=validate.Regexp(BRANCH_PATTERN))]
CardinalityFields = Annotated[
    list[NonEmptyStr],
    fields.List(NON_EMPTY_STRING_FIELD, validate=validate.Length(min=0, max=5)),
]
ConditionSemVer = Annotated[str, fields.String(validate=validate.Regexp(CONDITION_VERSION_PATTERN))]
Date = Annotated[str, fields.String(validate=validate.Regexp(DATE_PATTERN))]
Interval = Annotated[str, fields.String(validate=validate.Regexp(INTERVAL_PATTERN))]
MaxSignals = Annotated[int, fields.Integer(validate=validate.Range(min=1))]
NewTermsFields = Annotated[
    list[NonEmptyStr], fields.List(NON_EMPTY_STRING_FIELD, validate=validate.Length(min=1, max=3))
]
PositiveInteger = Annotated[int, fields.Integer(validate=validate.Range(min=1))]
RiskScore = Annotated[int, fields.Integer(validate=validate.Range(min=1, max=100))]
RuleName = Annotated[str, fields.String(validate=elastic_rule_name_regexp(NAME_PATTERN))]
SemVer = Annotated[str, fields.String(validate=validate.Regexp(VERSION_PATTERN))]
SemVerMinorOnly = Annotated[str, fields.String(validate=validate.Regexp(MINOR_SEMVER))]
Sha256 = Annotated[str, fields.String(validate=validate.Regexp(SHA256_PATTERN))]
SubTechniqueURL = Annotated[str, fields.String(validate=validate.Regexp(SUBTECHNIQUE_URL))]
TacticURL = Annotated[str, fields.String(validate=validate.Regexp(TACTIC_URL))]
TechniqueURL = Annotated[str, fields.String(validate=validate.Regexp(TECHNIQUE_URL))]
ThresholdValue = Annotated[int, fields.Integer(validate=validate.Range(min=1))]
TimelineTemplateId = Annotated[str, fields.String(validate=elastic_timeline_template_id_validator())]
TimelineTemplateTitle = Annotated[str, fields.String(validate=elastic_timeline_template_title_validator())]
UUIDString = Annotated[str, fields.String(validate=validate.Regexp(UUID_PATTERN))]

# experimental machine learning features and releases
MachineLearningType = Literal[MACHINE_LEARNING_PACKAGES]
MACHINE_LEARNING_PACKAGES_LOWER = tuple(map(str.lower, MACHINE_LEARNING_PACKAGES))
MachineLearningTypeLower = Literal[MACHINE_LEARNING_PACKAGES_LOWER]

ActionTypeId = Literal[
    ".slack",
    ".slack_api",
    ".email",
    ".index",
    ".pagerduty",
    ".swimlane",
    ".webhook",
    ".servicenow",
    ".servicenow-itom",
    ".servicenow-sir",
    ".jira",
    ".resilient",
    ".opsgenie",
    ".teams",
    ".torq",
    ".tines",
    ".d3security",
]
EsDataTypes = Literal[
    "binary",
    "boolean",
    "keyword",
    "constant_keyword",
    "wildcard",
    "long",
    "integer",
    "short",
    "byte",
    "double",
    "float",
    "half_float",
    "scaled_float",
    "unsigned_long",
    "date",
    "date_nanos",
    "alias",
    "object",
    "flatten",
    "nested",
    "join",
    "integer_range",
    "float_range",
    "long_range",
    "double_range",
    "date_range",
    "ip_range",
    "ip",
    "version",
    "murmur3",
    "aggregate_metric_double",
    "histogram",
    "text",
    "text_match_only",
    "annotated-text",
    "completion",
    "search_as_you_type",
    "token_count",
    "dense_vector",
    "sparse_vector",
    "rank_feature",
    "rank_features",
    "geo_point",
    "geo_shape",
    "point",
    "shape",
    "percolator",
]

# definitions for the integration to index mapping unit test case
IGNORE_IDS = [
    "eb079c62-4481-4d6e-9643-3ca499df7aaa",
    "699e9fdb-b77c-4c01-995c-1c15019b9c43",
    "0c9a14d9-d65d-486f-9b5b-91e4e6b22bd0",
    "a198fbbd-9413-45ec-a269-47ae4ccf59ce",
    "0c41e478-5263-4c69-8f9e-7dfd2c22da64",
    "aab184d3-72b3-4639-b242-6597c99d8bca",
    "a61809f3-fb5b-465c-8bff-23a8a068ac60",
    "f3e22c8b-ea47-45d1-b502-b57b6de950b3",
    "fcf18de8-ad7d-4d01-b3f7-a11d5b3883af",
]
IGNORE_INDICES = [
    ".alerts-security.*",
    "logs-*",
    "metrics-*",
    "traces-*",
    "endgame-*",
    "filebeat-*",
    "packetbeat-*",
    "auditbeat-*",
    "winlogbeat-*",
]

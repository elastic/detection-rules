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
# ES|QL comments and string literals are blanked before a query is scanned, so that the FROM
# keyword, or something shaped like an index pattern, is never read out of prose or a query value
ESQL_COMMENTS_AND_LITERALS_REGEX = re.compile(r'"""(?:.|\n)*?"""|"(?:[^"\\\n]|\\.)*"|//[^\n]*|/\*(?:.|\n)*?\*/')
# An ES|QL query has one FROM clause per source, and subqueries nest them,
# e.g. `FROM (FROM logs-a-* | ...), (FROM logs-b-* | ...)`
ESQL_FROM_KEYWORD_REGEX = re.compile(r"\bFROM\b\s+", re.IGNORECASE)
# An ES|QL source list runs until the first pipe, the METADATA directive, or the end of the subquery
ESQL_FROM_SOURCES_TERMINATOR_REGEX = re.compile(r"\||\)|\bMETADATA\b", re.IGNORECASE)
ESQL_INDEX_PATTERN_REGEX = re.compile(r"^[\w.*\-]+$")
ESQL_DYNAMIC_FIELD_PREFIXES = ("Esql.", "Esql_priv.")
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
    "corelight",
    "endpoint",
    "jamf_protect",
    "network_traffic",
    "pfsense",
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
TACTIC_URL = r"^(https://attack.mitre.org/tactics/TA[0-9]+/|https://atlas.mitre.org/tactics/AML\.TA[0-9]+/)$"
TECHNIQUE_URL = r"^(https://attack.mitre.org/techniques/T[0-9]+/|https://atlas.mitre.org/techniques/AML\.T[0-9]+/)$"
SUBTECHNIQUE_URL = (
    r"^(https://attack.mitre.org/techniques/T[0-9]+/[0-9]+/|https://atlas.mitre.org/techniques/AML\.T[0-9]+\.[0-9]+/)$"
)
MACHINE_LEARNING = "machine_learning"
QUERY = "query"
QUERY_FIELD_OP_EXCEPTIONS = ["powershell.file.script_block_text", "o365.audit.Members"]

# we had a bad rule ID make it in before tightening up the pattern, and so we have to let it bypass
KNOWN_BAD_RULE_IDS = Literal["119c8877-8613-416d-a98a-96b6664ee73a5", "7eb54028-ca72-4eb7-8185-b6864572347db"]
KNOWN_BAD_DEPRECATED_DATES = Literal["2021-03-03"]
# Known Null values that cannot be handled in TOML due to lack of Null value support via compound dicts
KNOWN_NULL_ENTRIES = [{"rule.actions": "frequency.throttle"}]
# Action type IDs (e.g. .cases, .workflows) that do not support frequency/throttle; do not add frequency to these
SYSTEM_ACTION_TYPE_IDS = (".cases", ".workflows")
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

# Controlled tag vocabulary for unit-test casing/prefix checks.
EXPECTED_RULE_TAGS = [
    "Data Source: APM",
    "Data Source: AWS",
    "Data Source: AWS Bedrock",
    "Data Source: AWS CloudTrail",
    "Data Source: AWS Sign-In",
    "Data Source: AWS VPC Flow Logs",
    "Data Source: Active Directory",
    "Data Source: Amazon Web Services",
    "Data Source: Auditd Manager",
    "Data Source: Azure",
    "Data Source: Azure Activity Logs",
    "Data Source: Azure OpenAI",
    "Data Source: Azure Platform Logs",
    "Data Source: Check Point Harmony Email Logs",
    "Data Source: CrowdStrike Falcon",
    "Data Source: Crowdstrike",
    "Data Source: CyberArk PAS",
    "Data Source: Elastic Defend",
    "Data Source: Elastic Defend for Containers",
    "Data Source: Elastic Endgame",
    "Data Source: Entra ID Audit Logs",
    "Data Source: Entra ID Protection Logs",
    "Data Source: Entra ID Sign-In",
    "Data Source: Entra ID Sign-In Logs",
    "Data Source: File Integrity Monitoring",
    "Data Source: Fortinet",
    "Data Source: GCP",
    "Data Source: GitHub Code Scanning Logs",
    "Data Source: Github",
    "Data Source: Google Cloud Platform",
    "Data Source: Google SecOps",
    "Data Source: Google Workspace",
    "Data Source: Google Workspace User Log Events",
    "Data Source: Jamf Protect",
    "Data Source: Kubernetes",
    "Data Source: macOS Security Events",
    "Data Source: Microsoft 365",
    "Data Source: Microsoft Defender XDR",
    "Data Source: Microsoft Defender for Cloud Alerts",
    "Data Source: Microsoft Defender for Identity",
    "Data Source: Microsoft Defender for Office 365",
    "Data Source: Microsoft Entra ID Sign-In Logs",
    "Data Source: Microsoft Exchange Online Logs",
    "Data Source: Microsoft Graph",
    "Data Source: Microsoft Purview",
    "Data Source: Microsoft Sentinel",
    "Data Source: Network Packet Capture",
    "Data Source: Network Traffic",
    "Data Source: Okta",
    "Data Source: PAN-OS",
    "Data Source: PowerShell Logs",
    "Data Source: Rapid7 Threat Command",
    "Data Source: SentinelOne",
    "Data Source: SonicWall",
    "Data Source: Splunk",
    "Data Source: Suricata",
    "Data Source: Sysmon",
    "Data Source: Windows Security Event Logs",
    "Data Source: Windows System Event Logs",
    "Data Source: Wiz",
    "Data Source: Zoom",
    "Domain: Cloud",
    "Domain: Container",
    "Domain: Containers",
    "Domain: Email",
    "Domain: Endpoint",
    "Domain: GenAI",
    "Domain: Identity",
    "Domain: LLM",
    "Domain: Network",
    "Domain: OT/IoT",
    "Domain: SaaS",
    "Mitre Atlas: *",
    "Noise: High",
    "Noise: Low",
    "Noise: Medium",
    "Noise: Unknown",
    "OS: Linux",
    "OS: Windows",
    "OS: macOS",
    "Performance: Fast",
    "Performance: Normal",
    "Performance: Slow",
    "Performance: Unknown",
    "Performance: Very Slow",
    "Platform: AWS",
    "Platform: Azure",
    "Platform: Entra ID",
    "Platform: GCP",
    "Platform: GitHub",
    "Platform: Google Workspace",
    "Platform: Kubernetes",
    "Platform: Linux",
    "Platform: Microsoft 365",
    "Platform: Okta",
    "Platform: Windows",
    "Platform: Wiz",
    "Platform: macOS",
    "Profile: Aggressive",
    "Profile: Beta",
    "Profile: Recommended",
    "Promotion: External Alerts",
    "Resources: Investigation Guide",
    "Resources: LLM",
    "Resources: OS Query",
    "Resources: Workflow",
    "Rule Type: BBR",
    "Rule Type: Custom Query (KQL)",
    "Rule Type: ES|QL",
    "Rule Type: Event Correlation (EQL)",
    "Rule Type: Higher-Order",
    "Rule Type: Higher-Order Rule",
    "Rule Type: Indicator Match",
    "Rule Type: ML",
    "Rule Type: Machine Learning",
    "Rule Type: New Terms",
    "Rule Type: Threshold",
    "Rule Type: Threat Match",
    "Service: AWS Backup",
    "Service: AWS Bedrock",
    "Service: AWS CloudFormation",
    "Service: AWS CloudWatch",
    "Service: AWS Config",
    "Service: AWS Detective",
    "Service: AWS DynamoDB",
    "Service: AWS EC2",
    "Service: AWS EFS",
    "Service: AWS EKS",
    "Service: AWS EventBridge",
    "Service: AWS GuardDuty",
    "Service: AWS IAM",
    "Service: AWS KMS",
    "Service: AWS Lambda",
    "Service: AWS Organizations",
    "Service: AWS RDS",
    "Service: AWS Route 53",
    "Service: AWS S3",
    "Service: AWS SES",
    "Service: AWS Sign-In",
    "Service: AWS SNS",
    "Service: AWS SQS",
    "Service: AWS SSM",
    "Service: AWS STS",
    "Service: AWS Secrets Manager",
    "Service: AWS WAF",
    "Service: AWS Security Hub",
    "Service: Apache HTTP Server",
    "Service: Apache Tomcat",
    "Service: Azure Event Hubs",
    "Service: Azure Functions",
    "Service: Azure Key Vault",
    "Service: Azure OpenAI",
    "Service: Azure Storage",
    "Service: GCP BigQuery",
    "Service: GCP Cloud Functions",
    "Service: GCP Cloud Storage",
    "Service: GCP Compute Engine",
    "Service: GCP Secret Manager",
    "Service: GitHub Actions",
    "Service: GitHub Code Scanning",
    "Service: IIS",
    "Service: Microsoft Exchange Online",
    "Service: Microsoft OneDrive",
    "Service: Microsoft Purview",
    "Service: Microsoft SharePoint",
    "Service: Microsoft Teams",
    "Service: Nginx",
    "Tactic: Collection",
    "Tactic: Command and Control",
    "Tactic: Credential Access",
    "Tactic: Defense Evasion",
    "Tactic: Defense Impairment",
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
    "Tactic: Stealth",
    "Threat: AiTM Phishing",
    "Threat: BPFDoor",
    "Threat: Browser Extension Abuse",
    "Threat: Brute Force",
    "Threat: ClickFix",
    "Threat: Cloud VM Execution",
    "Threat: Cobalt Strike",
    "Threat: Container Escape",
    "Threat: Cryptomining",
    "Threat: Device Code Phishing",
    "Threat: DLL Side-Load",
    "Threat: Download Tool Abuse",
    "Threat: Dynamic DNS",
    "Threat: Encoding-Based Obfuscation",
    "Threat: IMDS Credential Theft",
    "Threat: Impossible Travel",
    "Threat: Information Stealer",
    "Threat: Installer Abuse",
    "Threat: Lightning Framework",
    "Threat: Living off the Land",
    "Threat: LLMjacking",
    "Threat: LNK/Shortcut Abuse",
    "Threat: Log4Shell",
    "Threat: Masquerading",
    "Threat: OAuth App Consent",
    "Threat: Orbit",
    "Threat: Protocol Tunneling",
    "Threat: Ransomware",
    "Threat: React2Shell",
    "Threat: Remote Management Tool Abuse",
    "Threat: Reverse Shell",
    "Threat: Rootkit",
    "Threat: Script-Based Execution",
    "Threat: Supply Chain",
    "Threat: Suspicious TLD",
    "Threat: TripleCross",
    "Threat: Unauthorized AI Usage",
    "Threat: Vulnerability Exploit",
    "Threat: Vulnerable Driver",
    "Threat: Web Application Attack",
    "Threat: Web Service Abuse",
    "Threat: Web Shell",
    "Threat: WebDAV Abuse",
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
    "Vuln: CVE-2018-20781",
    "Vuln: CVE-2019-14287",
    "Vuln: CVE-2020-0601",
    "Vuln: CVE-2020-1030",
    "Vuln: CVE-2020-1048",
    "Vuln: CVE-2020-1337",
    "Vuln: CVE-2020-9613",
    "Vuln: CVE-2020-9614",
    "Vuln: CVE-2020-9615",
    "Vuln: CVE-2021-26857",
    "Vuln: CVE-2021-26858",
    "Vuln: CVE-2021-4034",
    "Vuln: CVE-2021-41379",
    "Vuln: CVE-2021-42278",
    "Vuln: CVE-2021-44228",
    "Vuln: CVE-2021-44521",
    "Vuln: CVE-2022-0492",
    "Vuln: CVE-2022-26923",
    "Vuln: CVE-2022-37706",
    "Vuln: CVE-2022-38028",
    "Vuln: CVE-2023-4911",
    "Vuln: CVE-2023-50164",
    "Vuln: CVE-2024-47076",
    "Vuln: CVE-2024-47175",
    "Vuln: CVE-2024-47176",
    "Vuln: CVE-2024-47177",
    "Vuln: CVE-2024-7262",
    "Vuln: CVE-2024-7263",
    "Vuln: CVE-2025-1975",
    "Vuln: CVE-2025-32463",
    "Vuln: CVE-2025-33053",
    "Vuln: CVE-2025-40536",
    "Vuln: CVE-2025-40551",
    "Vuln: CVE-2025-48384",
    "Vuln: CVE-2025-49844",
    "Vuln: CVE-2025-53770",
    "Vuln: CVE-2025-53771",
    "Vuln: CVE-2025-55182",
    "Vuln: CVE-2025-55241",
    "Vuln: CVE-2025-66478",
    "Vuln: CVE-2026-20253",
    "Vuln: CVE-2026-20841",
    "Vuln: CVE-2026-24061",
    "Vuln: CVE-2026-24858",
    "Vuln: CVE-2026-29093",
    "Vuln: CVE-2026-31431",
    "Vuln: CVE-2026-3888",
    "Vuln: CVE-2026-41940",
    "Vuln: CVE-2026-53413",
    "Vuln: CVE-2026-54121",
    "Vuln: CVE-2026-65400",
    "Vuln: CVE-2026-81578",
    "Vuln: CVE-2026-82078",
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
RiskScore = Annotated[int, fields.Integer(validate=validate.Range(min=0, max=100))]
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
    ".workflows",
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

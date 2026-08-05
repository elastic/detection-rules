# XDR / SIEM Rule Tag Taxonomy

Governed `Category: Value` tags for prebuilt detection rules. Used by Copilot PR review
(`.github/instructions/rules.instructions.md`), Kibana faceted search, and agentic workflows.

The casing-canonical vocabulary lives in `EXPECTED_RULE_TAGS`
(`detection_rules/schemas/definitions.py`). Full required-tag enforcement for new
categories is deferred; listing a tag there enables prefix/casing checks only.

## Mental model

| Question | Tag |
| --- | --- |
| Where in the XDR stack? | `Domain:` |
| Which ecosystem is in scope? | `Platform:` |
| Which telemetry / log stream? | `Data Source:` |
| Which product or component? | `Service:` (optional) |

Also tag how the rule is built (`Rule Type:`), ATT&CK tactics (`Tactic:`), OS when
endpoint-scoped (`OS:`), and analyst affordances (`Resources:`).

## Categories

| Category | Prefix | Required? | Notes |
| --- | --- | --- | --- |
| Domain | `Domain:` | Yes (≥1) | Attack surface; multi-domain allowed |
| Platform | `Platform:` | Yes (≥1) | Target ecosystem; not the log source |
| Data Source | `Data Source:` | Yes (when telemetry-bound) | Specific stream; one canonical spelling |
| OS | `OS:` | Endpoint / OS dirs | `Windows`, `Linux`, `macOS` |
| Tactic | `Tactic:` | Yes | Must match `[[rule.threat]]` |
| Rule Type | `Rule Type:` | Yes (≥1) | Engine / construction type |
| Service | `Service:` | Optional | Prefer when a specific service is targeted |
| Vulnerability | `Vuln:` | Optional | `CVE-YYYY-NNNNN` when exploit-specific |
| Threat | `Threat:` | Optional | Named exploit/campaign only — not actors/malware families on generic rules |
| MITRE ATLAS | `Mitre Atlas:` | GenAI when applicable | Technique IDs (e.g. `T0051`) |
| Profile | `Profile:` | Optional | `Recommended`, `Aggressive`, `Beta` |
| Resources | `Resources:` | When present | Investigation Guide, LLM, Workflow, OS Query |

Legacy prefixes such as `Use Case:` and `Promotion:` remain valid during migration.

## Domain values

`Endpoint`, `Cloud`, `Container` (legacy enforced spelling), `Containers`, `Network`,
`Identity`, `SaaS`, `Email`, `GenAI`, `OT/IoT`.

Do **not** invent domains for storage, web/app servers, or threat intelligence — use
`Service:` or `Rule Type:` instead.

## Platform values

`AWS`, `Azure`, `Entra ID`, `GCP`, `Google Workspace`, `Microsoft 365`, `Okta`,
`GitHub`, `Kubernetes`, `Windows`, `Linux`, `macOS`, `Elastic`, `Wiz`, `FortiGate`.

## Data Source values

Prefer the concrete telemetry name over the vendor alone. Preserve dual/legacy tags
still required by index-based unit tests (for example AWS rules still need both
`Data Source: AWS` and `Data Source: Amazon Web Services`).

**Cloud:** `AWS VPC Flow Logs`, `AWS Bedrock Invocation Logs`, `Azure Activity Logs`,
`Azure Platform Logs`, `Azure OpenAI Logs`, `GCP Audit Logs`

**Identity:** `Entra ID Audit Logs`, `Entra ID Protection Logs`, `Okta System Logs`,
`Active Directory Logs`

**SaaS:** `M365 Audit Logs`, `Microsoft Graph Activity Logs`,
`Google Workspace Audit Logs`, `GitHub Audit Logs`, `GitHub Code Scanning Logs`,
`Zoom Webhook Events`

**Endpoint:** `Elastic Defend`, `Elastic Endgame`, `Elastic Defend for Containers`,
`Windows Security Event Logs`, `Windows System Event Logs`, `Windows Sysmon Logs`,
`PowerShell Logs`, `Linux Auditd Logs`, `File Integrity Monitoring`,
`CrowdStrike Falcon Logs`, `SentinelOne Logs`, `Jamf Protect Event Logs`,
`Microsoft Defender for Endpoint Logs`

**Network:** `Network Packet Capture`, `Suricata Logs`, `PAN-OS Logs`,
`Fortinet FortiGate Logs`, `SonicWall Firewall Logs`

**Email / security tools / other:** `Microsoft Exchange Online Logs`,
`Microsoft Defender for Office 365 Logs`, `Check Point Harmony Email Logs`,
`Microsoft Purview Logs`, `Microsoft Defender for Cloud Alerts`,
`Microsoft Defender for Identity Alerts`, `Microsoft Sentinel Forwarded Events`,
`Splunk Forwarded Events`, `Wiz Findings`, `Rapid7 Threat Command Feeds`,
`Google SecOps Forwarded Events`, `Elastic APM Logs`,
`Kubernetes API Server Audit Logs`

### Deferred (casing conflicts in existing rules)

Do **not** add these to `EXPECTED_RULE_TAGS` until rules are normalized:

- `Data Source: AWS CloudTrail` (conflicts with `AWS Cloudtrail`)
- `Data Source: Entra ID Sign-In Logs` (conflicts with `Sign-in Logs` / `Sign-in logs`)

## Service values

Prefix cloud services with the vendor. Web/app servers usually need no vendor prefix.

**AWS:** S3, Lambda, DynamoDB, IAM, EC2, RDS, KMS, STS, SES, SNS, SQS, SSM,
Secrets Manager, CloudFormation, GuardDuty, WAF, Route 53, Bedrock

**Azure:** Key Vault, Storage, Functions, Event Hubs, OpenAI

**GCP:** BigQuery, Cloud Functions, Cloud Storage, Compute Engine

**GitHub:** Actions, Code Scanning

**Microsoft 365:** Teams, SharePoint, OneDrive, Exchange Online, Purview

**Web / app servers:** IIS, Nginx, Apache HTTP Server, Apache Tomcat

## Rule Type mapping

| Rule `type` / case | Tag(s) |
| --- | --- |
| `esql` | `Rule Type: ESQL` |
| `query` (KQL) | `Rule Type: Custom Query (KQL)` |
| `saved_query` | `Rule Type: Custom Query (KQL)` (same KQL construction tag) |
| `eql` | `Rule Type: Event Correlation (EQL)` |
| `threat_match` | Prefer `Rule Type: Indicator Match` (taxonomy). Legacy `Rule Type: Threat Match` remains valid on existing rules; Copilot may flag for rename but does not fail unit tests. |
| `threshold` | `Rule Type: Threshold` |
| `new_terms` | `Rule Type: New Terms` |
| `machine_learning` | `Rule Type: Machine Learning` **and** `Rule Type: ML` |
| Building block | `Rule Type: BBR` |
| Higher-order | `Rule Type: Higher-Order` (legacy `Higher-Order Rule` still valid) |

## Compatibility notes

- Keep `Domain: Container` on rules that unit tests already require until a coordinated
  rename to `Domain: Containers`.
- Copilot may suggest additive `Platform:` / `Service:` / `Vuln:` / `Profile:` tags now;
  required enforcement for those categories will land in a follow-up with broader rule
  remapping.
- Taxonomy names may differ from legacy short tags still present on rules
  (e.g. `SentinelOne` vs `SentinelOne Logs`); both remain valid until migration.

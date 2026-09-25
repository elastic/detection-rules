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
| How noisy / costly is this rule in fleet? | `Noise:` / `Performance:` / `Profile:` |
| Which threat pattern does it cover? | `Threat:` (optional, multi-label) |

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
| Threat | `Threat:` | Optional | Operational threat categories and/or named exploit/campaign tags; multi-label OK |
| Noise | `Noise:` | Optional (exactly one when set) | Fleet alert volume: `Low`, `Medium`, `High`, `Unknown` |
| Performance | `Performance:` | Optional (exactly one when set) | Rule exec cost: `Fast`, `Normal`, `Slow`, `Very Slow`, `Unknown` |
| MITRE ATLAS | `Mitre Atlas:` | GenAI detections | Technique IDs (`AML.T0051` or short `T0051`) |
| Profile | `Profile:` | Optional | `Recommended`, `Aggressive`, `Beta` |
| Resources | `Resources:` | When present | Investigation Guide, LLM, Workflow, Osquery |
| Use Case | `Use Case:` | Legacy | Still valid during migration |
| Promotion | `Promotion:` | Legacy | Still valid during migration |

## Domain values

`Endpoint`, `Cloud`, `Container` (legacy enforced spelling), `Containers`, `Network`,
`Identity`, `SaaS`, `Email`, `GenAI`, `OT/IoT`.

Use `Domain: GenAI` for rules that detect threats against or via generative AI systems
(agents, MCP, foundation-model APIs, model artifacts). Those rules should carry
`Mitre Atlas:` technique IDs. A rule that calls a model uses `Resources: LLM`.

Do **not** invent domains for storage, web/app servers, or threat intelligence — use
`Service:` or `Rule Type:` instead.

## Resources: LLM — rules that call an LLM

`Resources: LLM` is the **user-visible** tag that a detection invokes a large language
model. Customers use it in Kibana to find rules that require Elastic Inference Service
(or another LLM connector) and incur token cost.

**Add `Resources: LLM` when** the rule `query` uses the ES|QL `COMPLETION` command
(typically `| COMPLETION ... WITH { "inference_id": "..." }`).

**Do not add `Resources: LLM` when** the rule only detects GenAI/LLM *threats*
(`Domain: GenAI` + `Mitre Atlas:` instead), or when an investigation guide merely
mentions LLMs.

COMPLETION rules keep their existing attack-surface `Domain:` (Endpoint, Identity,
…). Do not add `Domain: GenAI` only because the query calls a model.

## Platform values

`AWS`, `Azure`, `Entra ID`, `GCP`, `Google Workspace`, `Microsoft 365`, `Okta`,
`GitHub`, `Kubernetes`, `Windows`, `Linux`, `macOS`, `Wiz`, `Anthropic`.

Legacy `Platform: Elastic` and `Platform: FortiGate` may still appear on rules;
prefer `Data Source:` / `Service:` for those products.

## Data Source values

Prefer the concrete telemetry name over the vendor alone. Preserve dual/legacy tags
still required by index-based unit tests (for example AWS rules still need both
`Data Source: AWS` and `Data Source: Amazon Web Services`).

**Cloud:** `AWS VPC Flow Logs`, `AWS CloudTrail`, `AWS Bedrock`, `AWS Sign-In`,
`Azure Activity Logs`, `Azure Platform Logs`, `Azure OpenAI`, `GCP Audit Logs`

**Identity:** `Entra ID Audit Logs`, `Entra ID Protection Logs`,
`Entra ID Sign-In Logs`, `Okta System Logs`, `Active Directory`

**SaaS:** `Microsoft 365`, `Microsoft Graph Activity Logs`,
`Google Workspace Audit Logs`, `GitHub Audit Logs`, `GitHub Code Scanning Logs`,
`Zoom`, `Anthropic Audit Logs`

**Endpoint:** `Elastic Defend`, `Elastic Endgame`, `Elastic Defend for Containers`,
`Windows Security Event Logs`, `Windows System Event Logs`, `Sysmon`,
`PowerShell Logs`, `File Integrity Monitoring`, `CrowdStrike Falcon`,
`SentinelOne`, `Jamf Protect`, `Microsoft Defender XDR`

**Network:** `Network Packet Capture`, `Network Traffic`, `Suricata`, `PAN-OS`,
`Fortinet FortiGate`, `SonicWall Firewall Logs`

**Email / security tools / other:** `Microsoft Exchange Online Logs`,
`Microsoft Defender for Office 365`, `Check Point Harmony Email Logs`,
`Microsoft Purview`, `Microsoft Defender for Cloud Alerts`,
`Microsoft Defender for Identity`, `Microsoft Sentinel`,
`Splunk`, `Wiz`, `Rapid7 Threat Command`,
`Google SecOps`, `APM`,
`Kubernetes API Server Audit Logs`

The full allowed list (including vendor-only aliases) is in
[Canonical values](#canonical-values-from-expected_rule_tags).

### Dual / conflicting spellings

Both spellings may exist on rules and/or in `EXPECTED_RULE_TAGS`. Prefer the first
going forward; do not invent a third:

- `Data Source: AWS CloudTrail` vs `AWS Cloudtrail`
- `Data Source: Entra ID Sign-In Logs` vs `Sign-in Logs` / `Sign-in logs`
- `Resources: Osquery` vs `Resources: OS Query`

## Service values

Prefix cloud services with the vendor. Web/app servers usually need no vendor prefix.

**AWS:** S3, Lambda, DynamoDB, IAM, EC2, RDS, KMS, STS, SES, SNS, SQS, SSM,
Secrets Manager, CloudFormation, GuardDuty, WAF, Route 53, Bedrock, Backup,
CloudWatch, Config, Detective, EFS, EKS, EventBridge, Organizations, Sign-In,
Security Hub

**Azure:** Key Vault, Storage, Functions, Event Hubs, OpenAI

**GCP:** BigQuery, Cloud Functions, Cloud Storage, Compute Engine, Secret Manager

**GitHub:** Actions, Code Scanning

**Microsoft 365:** Teams, SharePoint, OneDrive, Exchange Online, Purview

**Web / app servers:** IIS, Nginx, Apache HTTP Server, Apache Tomcat

## Rule Type mapping

| Rule `type` / case | Tag(s) |
| --- | --- |
| `esql` | `Rule Type: ES\|QL` |
| `query` (KQL) | `Rule Type: Custom Query (KQL)` |
| `saved_query` | `Rule Type: Custom Query (KQL)` (same KQL construction tag) |
| `eql` | `Rule Type: Event Correlation (EQL)` |
| `threat_match` | Prefer `Rule Type: Indicator Match` (taxonomy). Legacy `Rule Type: Threat Match` remains valid on existing rules; Copilot may flag for rename but does not fail unit tests. |
| `threshold` | `Rule Type: Threshold` |
| `new_terms` | `Rule Type: New Terms` |
| `machine_learning` | `Rule Type: Machine Learning` **and** `Rule Type: ML` |
| Building block | `Rule Type: BBR` |
| Higher-order | `Rule Type: Higher-Order` (legacy `Higher-Order Rule` still valid) |

## Threat values

Two complementary uses of `Threat:` (both allowed; multi-label OK):

1. **Named exploit / campaign / malware** on rules that specifically target that entity
   (legacy examples: `Threat: Log4Shell`, `Threat: SolarWinds`, `Threat: Cobalt Strike`).
   Do **not** invent adversary-group or malware-family tags on generic behavioral rules.
2. **Operational threat categories** from the managed catalog (fleet tagging pipeline), e.g.
   `Threat: Brute Force`, `Threat: Living off the Land`, `Threat: Ransomware`,
   `Threat: Supply Chain`, `Threat: Vulnerable Driver`, `Threat: Device Code Phishing`.
   Prefer catalog spellings in `EXPECTED_RULE_TAGS`; do not invent near-synonyms.

## Noise / Performance / Profile

Fleet-derived operational tags (usually applied by the tagging pipeline, not
hand-authored). Exactly one `Noise:` and one `Performance:` when those families are
present. At most one `Profile:`.

### Noise

Fleet alert volume over a telemetry window (typically **30 days**).

| Metric | Meaning |
| --- | --- |
| `global_alerts` / `global_clusters` | Total alerts and distinct clusters in the window |
| `global_density` | `global_alerts / global_clusters` |
| `global_noise` | Mean over days-with-alerts of `alerts / distinct clusters that day` |

**Percentile cuts** on `global_noise` among rules that fired: Low cut ≈ **p25**, High cut
≈ **p85**. For `windows` / `linux` / `macos` / `aws` / `azure` / `gcp` / `google workspace` / `microsoft 365` / `okta` / `github`  with enough firing rules (≥30),
cuts are **per-platform**; other platforms use a shared fleet fallback.

| Tag | When (defaults) |
| --- | --- |
| `Noise: Low` | Rule age ≥ **60 days**, and any of: (A) has telem, density ≤ **300**, and (`global_noise` ≤ Low cut **or** alerts ≤ **100**); (B) sparse escape — density ≤ **15** and alerts ≤ **150**; (C) **zero** telem and age ≥ **180 days** (long-lived quiet / low adoption treated as Low) |
| `Noise: High` | Has telem and (`global_noise` ≥ High cut **or** density > **400**); **or** age &lt; **60 days** with alerts &gt; **100** and clusters ≥ **5** (loud while still young) |
| `Noise: Medium` | Has telem and is neither Low nor High (including young mid-volume rules that are not yet High) |
| `Noise: Unknown` | Zero telem and age &lt; **180 days**; **or** age &lt; **60 days** with alerts ≤ **100** — too new (or too little signal) to tell quiet from low adoption |

Evaluation favors High when density/noise is extreme. Young rules (&lt;60 days) never get
`Noise: Low` from telemetry alone (low volume → Unknown; already loud → High or Medium).

### Performance

Rule execution cost from metrics traces (joined by rule name). Classification uses
**average** and **p95** duration plus counts of clusters that saw a ≥30s execution.
Fleet medians are tightly clustered, so cuts are absolute ms thresholds:

| Tag | When (defaults) |
| --- | --- |
| `Performance: Very Slow` | avg ≥ **5000 ms (5 s)** **or** p95 ≥ **15000 ms (15 s)** **or** ≥25 clusters with a ≥30 s execution |
| `Performance: Slow` | avg ≥ **2000 ms (2 s)** **or** p95 ≥ **5000 ms (5 s)** **or** ≥10 clusters with a ≥30 s execution |
| `Performance: Fast` | avg ≤ **400 ms** **and** p95 ≤ **1000 ms (1 s)** **and** no ≥30 s slow clusters **and** ≥5 clusters sampled |
| `Performance: Normal` | Sample is sufficient to classify (see Unknown), **and** the rule is not Fast, Slow, or Very Slow — typical mid-range exec cost (e.g. avg between ~400 ms and 2 s, or Fast-like avg but p95/sample gates not met) |
| `Performance: Unknown` | No metrics, **or** low sample: &lt; **50** executions **or** &lt; **3** clusters in the window |

Evaluation order: Unknown (insufficient data) → Very Slow → Slow → Fast → else **Normal**.
Fast is intentionally strict (env-dependent).

### Profile

Deployment posture: `Recommended`, `Aggressive`, or `Beta`. `Beta` is manual /
separate. `Recommended` and `Aggressive` are scored from severity + noise +
performance + threat coverage.

#### Profile: Recommended

Rules tagged `Profile: Recommended` are high-confidence detections suited for broad
enablement. They combine strong signal value (severity and coverage of a tracked
threat) with low operational cost (manageable alert volume and query performance),
making them a curated starting set that can be turned on without significant tuning.

A rule earns **Recommended** when its **profile score reaches 7 or higher**. The
score is the sum of four factors:

| Factor | Values → points |
| --- | --- |
| **Severity** | critical **+3**, high **+2**, medium **+1**, low **0** |
| **Noise** | Low **+3**, Medium **+1**, High **−2**, Unknown **0** |
| **Performance** | Fast **+2**, Normal **+1**, Slow **−1**, Very Slow **−2**, Unknown **0** |
| **Threat coverage** | maps to a tracked / managed `Threat:` tag (e.g. Ransomware, AiTM Phishing, Container Escape): present **+4**, absent **0** |

Threat coverage carries the highest weight because these tags represent the
mechanics we actively observe and prioritize.

**Hard gates** (override the numeric score):

- A rule with `Noise: High` is **never** Recommended — it is tagged
  `Profile: Aggressive` instead, regardless of score.
- A rule with `severity: low` is **never** Recommended.

At threshold 7, medium-severity rules usually need a Threat tag to clear
Recommended (medium without threat maxes at 6 with Low noise + Fast performance).
High + Low noise + Fast can reach 7 without a Threat tag.

#### Profile: Aggressive

Rules tagged `Profile: Aggressive` are detections that are usually **not** suitable
as a default broad-enable set. They either generate high alert volume in fleet
telemetry, or score poorly on the same signal-vs-cost model used for Recommended
(weak severity/threat coverage and/or high operational cost such as Slow
performance).

A rule is tagged **Aggressive** when **either**:

1. **`Noise: High`** — always Aggressive, regardless of score (hard gate); or
2. **`profile score < 2`** — and severity is not `low` (low severity never gets a
   Profile tag; it stays mid-band even if the numeric score is low).

Example of (2): medium severity (+1) + Medium noise (+1) + Slow performance (−1) +
no Threat tag (0) → score **1** → Aggressive (even though noise is not High).

Intended for environments that accept higher alert volume, slower queries, or are
tuning coverage aggressively — not as the first wave of enablement.

#### Mid band

Rules that are neither Recommended nor Aggressive receive **no** `Profile:` tag
(including all `severity: low` rules that are not High noise).

## Compatibility notes

- Keep `Domain: Container` on rules that unit tests already require until a coordinated
  rename to `Domain: Containers`.
- Copilot may suggest additive `Platform:` / `Service:` / `Vuln:` / catalog `Threat:` tags
  now; do **not** invent `Noise:` / `Performance:` / `Profile: Recommended|Aggressive`
  without telemetry. Required enforcement for those categories will land with broader
  rule remapping.
- Taxonomy names may differ from legacy short tags still present on rules
  (e.g. `SentinelOne` vs `SentinelOne Logs`); both remain valid until migration.

## Canonical values (from `EXPECTED_RULE_TAGS`)

This list mirrors `EXPECTED_RULE_TAGS` in `detection_rules/schemas/definitions.py`.

| Prefix | Values |
| --- | --- |
| Domain | Cloud, Containers, Email, Endpoint, GenAI, Identity, Network, OT/IoT, SaaS |
| Platform | AWS, Anthropic, Azure, Entra ID, GCP, GitHub, Google Workspace, Kubernetes, Linux, Microsoft 365, Okta, Windows, Wiz, macOS |
| OS | Linux, Windows, macOS |
| Rule Type | BBR, Custom Query (KQL), ES\|QL, Event Correlation (EQL), Higher-Order, Higher-Order Rule, Indicator Match, ML, Machine Learning, New Terms, Threshold, Threat Match |
| Noise | High, Low, Medium, Unknown |
| Performance | Fast, Normal, Slow, Unknown, Very Slow |
| Profile | Aggressive, Beta, Recommended |
| Resources | Investigation Guide, LLM, Osquery, Workflow |
| Promotion | External Alerts |
| Mitre Atlas | `*` (technique IDs) |
| Use Case | Active Directory Monitoring, Asset Visibility, Configuration Audit, Guided Onboarding, Identity and Access Audit, Log Auditing, Network Security Monitoring, Threat Detection, UEBA, Vulnerability |
| Tactic | Collection, Command and Control, Credential Access, Defense Evasion, Defense Impairment, Discovery, Execution, Exfiltration, Impact, Initial Access, Lateral Movement, Persistence, Privilege Escalation, Reconnaissance, Resource Development, Stealth |

**Data Source:** APM, AWS, AWS Bedrock, AWS CloudTrail, AWS Sign-In, AWS VPC Flow Logs, Active Directory, Amazon Bedrock, Amazon Web Services, Anthropic Audit Logs, Auditd Manager, Azure, Azure Activity Logs, Azure OpenAI, Azure Platform Logs, Check Point Harmony Email Logs, CrowdStrike Falcon, Crowdstrike, CyberArk PAS, Elastic Defend, Elastic Defend for Containers, Elastic Endgame, Entra Audit Logs, Entra ID Audit Logs, Entra ID Protection Logs, Entra ID Sign-In, Entra ID Sign-In Logs, File Integrity Monitoring, Fortinet, Fortinet FortiGate, GCP, GCP Audit Logs, GitHub Audit Logs, GitHub Code Scanning Logs, Github, Google Cloud Platform, Google SecOps, Google Workspace, Google Workspace Audit Logs, Google Workspace Device Logs, Google Workspace User Log Events, Jamf Protect, Kubernetes, Kubernetes API Server Audit Logs, Linux Sysmon Logs, macOS Security Events, Microsoft 365, Microsoft Defender XDR, Microsoft Defender for Cloud Alerts, Microsoft Defender for Identity, Microsoft Defender for Office 365, Microsoft Entra ID Sign-In Logs, Microsoft Exchange Online Logs, Microsoft Graph, Microsoft Graph Activity Logs, Microsoft Purview, Microsoft Sentinel, Network Packet Capture, Network Traffic, Okta, Okta System Logs, PAN-OS, PowerShell Logs, Rapid7 Threat Command, SentinelOne, SonicWall, SonicWall Firewall Logs, Splunk, Suricata, Sysmon, Windows Security Event Logs, Windows System Event Logs, Wiz, Zoom

**Service:** AWS Backup, AWS Bedrock, AWS CloudFormation, AWS CloudWatch, AWS Config, AWS Detective, AWS DynamoDB, AWS EC2, AWS EFS, AWS EKS, AWS EventBridge, AWS GuardDuty, AWS IAM, AWS KMS, AWS Lambda, AWS Organizations, AWS RDS, AWS Route 53, AWS S3, AWS SES, AWS Sign-In, AWS SNS, AWS SQS, AWS SSM, AWS STS, AWS Secrets Manager, AWS WAF, AWS Security Hub, Apache HTTP Server, Apache Tomcat, Azure Event Hubs, Azure Functions, Azure Key Vault, Azure OpenAI, Azure Storage, GCP BigQuery, GCP Cloud Functions, GCP Cloud Storage, GCP Compute Engine, GCP Secret Manager, GitHub Actions, GitHub Code Scanning, IIS, Microsoft Exchange Online, Microsoft OneDrive, Microsoft Purview, Microsoft SharePoint, Microsoft Teams, Nginx

**Threat:** AiTM Phishing, BPFDoor, Browser Extension Abuse, Brute Force, ClickFix, Cloud VM Execution, Cobalt Strike, Container Escape, Cryptomining, Device Code Phishing, DLL Side-Load, Download Tool Abuse, Dynamic DNS, Encoding-Based Obfuscation, IMDS Credential Theft, Impossible Travel, Information Stealer, Installer Abuse, Lightning Framework, Living off the Land, LLMjacking, LNK/Shortcut Abuse, Log4Shell, Masquerading, OAuth App Consent, Orbit, Protocol Tunneling, Ransomware, React2Shell, Remote Management Tool Abuse, Reverse Shell, Rootkit, Script-Based Execution, Supply Chain, Suspicious TLD, TripleCross, Unauthorized AI Usage, Vulnerability Exploit, Vulnerable Driver, Web Application Attack, Web Service Abuse, Web Shell, WebDAV Abuse

**Vuln:** `CVE-*` entries listed in `EXPECTED_RULE_TAGS`.

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
`GitHub`, `Kubernetes`, `Windows`, `Linux`, `macOS`, `Wiz`, `FortiGate`.

`Platform:` is the target ecosystem, not the vendor that authored the rule and not
where telemetry is stored. Do not tag `Platform: Elastic`.

## Data Source values

Prefer the concrete telemetry name over the vendor alone. Preserve dual/legacy tags
still required by index-based unit tests (for example AWS rules still need both
`Data Source: AWS` and `Data Source: Amazon Web Services`).

**Do not append `Logs` to a vendor/product already used as a data source.** Existing
rules keep `SentinelOne`, `Sysmon`, and `Crowdstrike`. Do not add `SentinelOne Logs`
or `Windows Sysmon Logs`. If the CrowdStrike name is expanded, use `CrowdStrike Falcon`
— never `CrowdStrike Falcon Logs`. `Logs` belongs only on distinct *stream* names
(`Windows Security Event Logs`, `Entra ID Sign-In Logs`, `AWS VPC Flow Logs`).

**Cloud:** `AWS CloudTrail`, `AWS VPC Flow Logs`, `AWS Sign-In`, `AWS Bedrock`,
`Azure Activity Logs`, `Azure Platform Logs`, `Azure OpenAI`, `GCP`

**Identity:** `Entra ID Audit Logs`, `Entra ID Protection Logs`,
`Entra ID Sign-In Logs`, `Okta`, `Active Directory`.
Existing rules may also carry `Data Source: Microsoft Entra ID Sign-In Logs` or
`Data Source: Entra ID Sign-In` (no "Logs"); keep those spellings.

**SaaS:** `Microsoft 365`, `Microsoft Graph`,
`Google Workspace`, `Google Workspace User Log Events`,
`Github`, `GitHub Code Scanning Logs`, `Zoom`

**Endpoint:** `Elastic Defend`, `Elastic Endgame`, `Elastic Defend for Containers`,
`Windows Security Event Logs`, `Windows System Event Logs`, `Sysmon`,
`PowerShell Logs`, `Auditd Manager`, `File Integrity Monitoring`,
`Crowdstrike` (same source as `CrowdStrike Falcon`; do not use both), `SentinelOne`,
`Jamf Protect`, `Microsoft Defender XDR`

**Network:** `Network Traffic`, `Network Packet Capture`, `Suricata`, `PAN-OS`,
`Fortinet`, `SonicWall`

**Email / security tools / other:** `Microsoft Exchange Online Logs`,
`Microsoft Defender for Office 365`, `Check Point Harmony Email Logs`,
`Microsoft Purview`, `Microsoft Defender for Identity`, `Microsoft Sentinel`,
`Splunk`, `Wiz`, `Rapid7 Threat Command`, `Google SecOps`, `APM`, `Kubernetes`

## Service values

Prefix cloud services with the vendor. Web/app servers usually need no vendor prefix.

**AWS:** S3, Lambda, DynamoDB, IAM, EC2, RDS, KMS, STS, SES, SNS, SQS, SSM,
Secrets Manager, CloudFormation, CloudWatch, Config, Detective, GuardDuty, WAF,
Route 53, Bedrock, EKS, EFS, EventBridge, Organizations, Backup, Sign-In

**Azure:** Key Vault, Storage, Functions, Event Hubs, OpenAI

**GCP:** BigQuery, Cloud Functions, Cloud Storage, Compute Engine

**GitHub:** Actions, Code Scanning

**Microsoft 365:** Teams, SharePoint, OneDrive, Exchange Online, Purview

**Web / app servers:** IIS, Nginx, Apache HTTP Server, Apache Tomcat

## Rule Type mapping

| Rule `type` / case | Tag(s) |
| --- | --- |
| `esql` | `Rule Type: ES|QL` |
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
- Do not add a `Data Source:` that only appends `Logs` (or `Falcon Logs`) to a
  vendor tag already on the rule. `Crowdstrike` / `CrowdStrike Falcon`, `SentinelOne`,
  and `Sysmon` are the product names; they are not `… Logs` tags.

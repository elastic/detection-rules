# Domain

Domain: tags identify the **security control plane or attack surface** a rule applies to. Domains describe **where in the XDR stack** adversary behavior occurs (endpoint, identity, cloud, etc.), independent of vendor, platform, or data source.

At least **one `Domain:` tag is required** per rule. Rules that span multiple attack surfaces may include **multiple “`Domain:”` tags**.

**User-Centric Faceted Search Example**

*"Show me all Identity-related detections I can enable for Entra ID."*

Facet filter:

- `Domain: Identity`

**XDR-Centric Use Case**

- Route detections into **domain-specific workflows** (Endpoint vs Identity vs Cloud).
- Enable agentic workflows to reason about **cross-domain attack chains**.

**Acceptable Values**

| Value | Description |
| :---- | :---- |
| `Domain: Endpoint` | Host-based detections \- processes, files, registry, OS-level activity |
| `Domain: Cloud` | Cloud infrastructure, platform control plane, and cloud workload runtime (AWS, Azure, GCP) |
| `Domain: Containers` | Container runtime and orchestration (Docker, containerd, Kubernetes) |
| `Domain: Network` | Network traffic, firewall, IDS/IPS, DNS, proxy |
| `Domain: Identity` | Identity providers, authentication, SSO, directory services (Entra ID, Okta, AD) |
| `Domain: SaaS` | SaaS application activity (M365, Google Workspace, Zoom, GitHub, Slack) |
| `Domain: Email` | Email security \- message trace, phishing, mail flow (Exchange, message trace) |
| `Domain: GenAI` | Generative AI and LLM security (Bedrock, Azure OpenAI, Ollama) |
| `Domain: OT/IoT` | Operational technology and IoT device security |

**Design Rationale**

The following were considered and intentionally excluded as domains:

- **Web / Application servers** \- covered by `Middleware:` tags; detection point is `Domain: Endpoint` or `Domain: Network`
- **Storage** \- covered by `Service:` tags (e.g., `Service: AWS S3`); detection point is `Domain: Cloud` or `Domain: SaaS`
- **Threat Intelligence** \- a detection method, not an attack surface; covered by `Rule Type: Threat Match`
- **Workload** \- ambiguous boundary with Cloud; cloud workload detections are tagged `Domain: Cloud` with the specific service captured by `Service:`

---

# Platform

Platform: tags identify the **target platform or ecosystem** the adversary behavior applies to. This is distinct from `Data Source:` (which is the telemetry) and complements `Domain:` (which is the attack surface). Likely, any integration will have a dedicated platform tag. This applies to 3rd-party promotions as well.

At least **one `Platform:` tag is required** per rule. A rule may have **multiple `Platform:` tags** if it spans platforms.

**User-Centric Faceted Search Example**

*"Show me all Identity detections for Entra ID."*

Facet filters:

- `Domain: Identity`
- `Platform: Entra ID`

**XDR-Centric Use Case**

- Align detections to **platform-specific threat models**.
- Enable agentic workflows to reason about **provider-specific behavior and abuse patterns**.

**Acceptable Values**

| Value | Typical Domain Context |
| :---- | :---- |
| `Platform: AWS` | Cloud, GenAI |
| `Platform: Azure` | Cloud |
| `Platform: Entra ID` | Identity |
| `Platform: GCP` | Cloud |
| `Platform: Google Workspace` | SaaS |
| `Platform: Microsoft 365` | SaaS, Email |
| `Platform: Okta` | Identity |
| `Platform: GitHub` | SaaS |
| `Platform: Kubernetes` | Containers |
| `Platform: Windows` | Endpoint |
| `Platform: Linux` | Endpoint |
| `Platform: macOS` | Endpoint |
| `Platform: Elastic` | Endpoint, Network |
| `Platform: Wiz` | Cloud |
| `Platform: FortiGate` | Network |

---

# Data Source

Data Source: tags identify the **originating telemetry or log source** used by the rule. This represents **where the data comes from** \- the specific log stream or integration \- not the target platform, service, or attack surface.

- Values must refer to the **actual telemetry source** (e.g., `AWS CloudTrail`, `Entra ID Sign-In Logs`), not the platform itself.
- Normalize casing and naming \- only **one canonical form** per data source (e.g., `CloudTrail`, not `Cloudtrail`).

**User-Centric Faceted Search Example**

*"Show me all rules that require Entra ID Sign-In Logs."*

Facet filter:

- `Data Source: Entra ID Sign-In Logs`

**XDR-Centric Use Case**

- Validate that required telemetry is **present and enabled**.
- Allow agentic workflows to confirm **data availability before activation**.

**Acceptable Values (Not Exhaustive)**

Cloud Providers

| Value | Platform | Description |
| :---- | :---- | :---- |
| `Data Source: AWS CloudTrail` | AWS | AWS API activity and management event logs |
| `Data Source: AWS VPC Flow Logs` | AWS | Network flow logs for AWS VPCs |
| `Data Source: AWS Bedrock Invocation Logs` | AWS | Bedrock model invocation and guardrail logs |
| `Data Source: Azure Activity Logs` | Azure | Azure resource management activity |
| `Data Source: Azure Platform Logs` | Azure | Azure platform-level diagnostic logs |
| `Data Source: Azure OpenAI Logs` | Azure | Azure OpenAI service request logs |
| `Data Source: GCP Audit Logs` | GCP | Google Cloud audit logging |

Identity Providers

| Value | Platform | Description |
| :---- | :---- | :---- |
| `Data Source: Entra ID Sign-In Logs` | Entra ID | Authentication and sign-in event logs |
| `Data Source: Entra ID Audit Logs` | Entra ID | Directory change and admin activity logs |
| `Data Source: Entra ID Protection Logs` | Entra ID | Identity protection risk event logs |
| `Data Source: Okta System Logs` | Okta | Okta system event logs |
| `Data Source: Active Directory Logs` | Windows | Active Directory replication and object logs |

SaaS & Collaboration

| Value | Platform | Description |
| :---- | :---- | :---- |
| `Data Source: M365 Audit Logs` | Microsoft 365 | Microsoft 365 unified audit logs |
| `Data Source: Microsoft Graph Activity Logs` | Azure/M365 | Graph API request and response logs |
| `Data Source: Google Workspace Audit Logs` | Google Workspace | Workspace admin and user activity logs |
| `Data Source: GitHub Audit Logs` | GitHub | GitHub organization and repo audit logs |
| `Data Source: GitHub Code Scanning Logs` | GitHub | Code scanning alert and result logs |
| `Data Source: Zoom Webhook Events` | SaaS | Zoom webhook event data |

Endpoint

| Value | Platform | Description |
| :---- | :---- | :---- |
| `Data Source: Elastic Defend` | Elastic | Elastic Defend endpoint telemetry |
| `Data Source: Elastic Endgame` | Elastic | Legacy Endgame endpoint telemetry |
| `Data Source: Elastic Defend for Containers` | Elastic | Container-specific Elastic Defend telemetry |
| `Data Source: Windows Security Event Logs` | Windows | Windows Security channel event logs |
| `Data Source: Windows System Event Logs` | Windows | Windows System channel event logs |
| `Data Source: Windows Sysmon Logs` | Windows | Sysmon process, network, and file monitoring logs |
| `Data Source: PowerShell Logs` | Windows | PowerShell script block and module logging |
| `Data Source: Linux Auditd Logs` | Linux | Linux audit framework event logs |
| `Data Source: File Integrity Monitoring` | Endpoint | FIM change detection events |
| `Data Source: CrowdStrike Falcon Logs` | Endpoint | CrowdStrike Falcon Data Replicator event logs |
| `Data Source: SentinelOne Logs` | Endpoint | SentinelOne Deep Visibility event logs |
| `Data Source: Jamf Protect Event Logs` | Endpoint | Jamf Protect macOS telemetry logs |
| `Data Source: Microsoft Defender for Endpoint Logs` | Endpoint | MDE alert and telemetry event logs |

Network & Firewall

| Value | Platform | Description |
| :---- | :---- | :---- |
| `Data Source: Network Packet Capture` | Network | Raw packet capture telemetry |
| `Data Source: Suricata Logs` | Network | Suricata IDS/IPS alert and protocol logs |
| `Data Source: PAN-OS Logs` | Network | Palo Alto Networks firewall event logs |
| `Data Source: Fortinet FortiGate Logs` | Network | FortiGate firewall event logs |
| `Data Source: SonicWall Firewall Logs` | Network | SonicWall firewall event logs |

Email & Messaging

| Value | Platform | Description |
| :---- | :---- | :---- |
| `Data Source: Microsoft Exchange Online Logs` | Email | Exchange Online mail flow and transport logs |
| `Data Source: Microsoft Defender for Office 365 Logs` | Email | Defender for Office 365 email threat event logs |
| `Data Source: Check Point Harmony Email Logs` | Email | Check Point email security event logs |

Security Tools & SIEM

| Value | Platform | Description |
| :---- | :---- | :---- |
| `Data Source: Microsoft Purview Logs` | M365 | Purview DLP and insider risk event logs |
| `Data Source: Microsoft Defender for Cloud Alerts` | Cloud | Defender for Cloud security alert findings |
| `Data Source: Microsoft Defender for Identity Alerts` | Identity | Defender for Identity alert event data |
| `Data Source: Microsoft Sentinel Forwarded Events` | SIEM | Sentinel forwarded event data |
| `Data Source: Splunk Forwarded Events` | SIEM | Splunk forwarded event data |
| `Data Source: Wiz Findings` | Cloud | Wiz cloud security posture findings |
| `Data Source: Rapid7 Threat Command Feeds` | TI | Rapid7 threat intelligence feed data |
| `Data Source: Google SecOps Forwarded Events` | SIEM | Google Security Operations forwarded data |
| `Data Source: Elastic APM Logs` | Elastic | Application Performance Monitoring telemetry |

Containers & Orchestration

| Value | Platform | Description |
| :---- | :---- | :---- |
| `Data Source: Kubernetes API Server Audit Logs` | Kubernetes | K8s API server audit event logs |

---

# Service

Service: tags identify a **specific service, application, or software component** targeted by a rule. These provide finer-grained context beyond the platform level and are critical for faceted search \- allowing users to combine `Platform:` with `Service:` to drill into exactly the coverage they need.

Services include cloud-native services (e.g., `AWS S3`, `Azure Key Vault`), SaaS applications (e.g., `Microsoft Teams`), and web/application servers (e.g., `IIS`, `Nginx`, `Apache Tomcat`).

- `Service:` tags are **optional** but strongly recommended when a rule targets a specific service.
- Prefix cloud service names with the **platform vendor** for clarity (e.g., `AWS S3`, not just `S3`).
- Web/app server names do not require a vendor prefix.

**User-Centric Faceted Search Example**

*"Show me detections specific to Azure Key Vault."*

Facet filter:

- `Service: Azure Key Vault`

**XDR-Centric Use Case**

- Enable **service-level threat coverage** analysis.
- Support targeted rule enablement during audits or incidents.

**Acceptable Values (Not Exhaustive)**

AWS

| Value |
| :---- |
| `Service: AWS S3` |
| `Service: AWS Lambda` |
| `Service: AWS DynamoDB` |
| `Service: AWS IAM` |
| `Service: AWS EC2` |
| `Service: AWS RDS` |
| `Service: AWS KMS` |
| `Service: AWS STS` |
| `Service: AWS SES` |
| `Service: AWS SNS` |
| `Service: AWS SQS` |
| `Service: AWS SSM` |
| `Service: AWS Secrets Manager` |
| `Service: AWS CloudFormation` |
| `Service: AWS GuardDuty` |
| `Service: AWS WAF` |
| `Service: AWS Route 53` |
| `Service: AWS Bedrock` |

Azure

| Value |
| :---- |
| `Service: Azure Key Vault` |
| `Service: Azure Storage` |
| `Service: Azure Functions` |
| `Service: Azure Event Hubs` |
| `Service: Azure OpenAI` |

GCP

| Value |
| :---- |
| `Service: GCP BigQuery` |
| `Service: GCP Cloud Functions` |
| `Service: GCP Cloud Storage` |
| `Service: GCP Compute Engine` |

GitHub

| Value |
| :---- |
| `Service: GitHub Actions` |
| `Service: GitHub Code Scanning` |

Microsoft 365

| Value |
| :---- |
| `Service: Microsoft Teams` |
| `Service: Microsoft SharePoint` |
| `Service: Microsoft OneDrive` |
| `Service: Microsoft Exchange Online` |
| `Service: Microsoft Purview` |

Web / Application Servers

| Value |
| :---- |
| `Service: IIS` |
| `Service: Nginx` |
| `Service: Apache HTTP Server` |
| `Service: Apache Tomcat` |

---

# OS

OS: tags identify the **operating system context** a rule applies to. These tags are used for host-based detections and ensure rules are only applied to supported operating systems.

OS tags are **optional**, unless enforced by directory structure or rule scope. Note: **all endpoint related tags should have OS tags.**

**User-Centric Faceted Search Example**

*"Show me all Linux-specific endpoint detections."*

Facet filter:

- `OS: Linux`

**XDR-Centric Use Case**

- Prevent misapplication of rules to unsupported systems.
- Enable OS-specific triage, response, and remediation workflows.

**Acceptable Values**

| Value | Description |
| :---- | :---- |
| `OS: Windows` | Microsoft Windows |
| `OS: Linux` | Linux distributions |
| `OS: macOS` | Apple macOS |

---

# Tactic

Tactic: tags map detections to **MITRE ATT\&CK tactics**, aligned with the rule's threat mapping. The tactic tags must match the tactics listed in the rule's `[[rule.threat]]` definition. **Tactic tags are required**.

**User-Centric Faceted Search Example**

*"Show me detections related to Initial Access."*

Facet filter:

- `Tactic: Initial Access`

**XDR-Centric Use Case**

- Enable ATT\&CK-based coverage analysis.
- Support kill-chain-aware investigation and agentic reasoning.

**Acceptable Values**

MITRE ATT\&CK tactics only:

| Value |
| :---- |
| `Tactic: Reconnaissance` |
| `Tactic: Resource Development` |
| `Tactic: Initial Access` |
| `Tactic: Execution` |
| `Tactic: Persistence` |
| `Tactic: Privilege Escalation` |
| `Tactic: Defense Evasion` |
| `Tactic: Credential Access` |
| `Tactic: Discovery` |
| `Tactic: Lateral Movement` |
| `Tactic: Collection` |
| `Tactic: Command and Control` |
| `Tactic: Exfiltration` |
| `Tactic: Impact` |

---

# Rule Type

Rule Type: tags describe **how a detection is constructed or evaluated** within Elastic Security. This reflects the detection engine or logic type rather than the threat itself.

At least **one Rule Type tag is required** per rule. Rule Type values align with the detection engine's rule type vocabulary as documented on the Elastic website.

**User-Centric Faceted Search Example**

*"Show me all machine learning-based detections."*

Facet filter:

- `Rule Type: Machine Learning`

**XDR-Centric Use Case**

- Differentiate deterministic vs probabilistic detections.
- Allow agentic workflows to reason differently about ML, correlation, and query-based rules.

**Acceptable Values**

| Value | Description |
| :---- | :---- |
| `Rule Type: ESQL` | Aggregated, transformed, or computed conditions |
| `Rule Type: Custom Query (KQL)` | Known field value, pattern, or boolean condition (KQL) |
| `Rule Type: Event Correlation (EQL)` | Ordered sequence of events or missing event (EQL) |
| `Rule Type: Indicator Match` | Events matching a known threat indicator |
| `Rule Type: Threshold` | Field value count exceeding a boundary |
| `Rule Type: Machine Learning` | Behavioral anomalies without a fixed pattern |
| `Rule Type: New Terms` | Field value appearing for the first time |
| `Rule Type: BBR` | Building block \- generates signals for other rules |
| `Rule Type: Higher-Order` | Correlates signals from BBRs or other rules |

---

# Vulnerability

Vuln: tags associate detections with **specific vulnerabilities or CVEs**. These are optional and primarily used for campaign-driven or exploit-specific detections.

- `Vuln:` tags are **optional**.
- Use the **standard CVE identifier format**.
- Apply when a rule is specifically designed to detect **exploitation of a known vulnerability**.

**User-Centric Faceted Search Example**

*"Show me detections related to active KEV vulnerabilities."*

Facet filter:

- `Vuln: CVE-2025-24813`

**XDR-Centric Use Case**

- Enable **vulnerability-driven detection** enablement.
- Support **rapid response** to emerging exploitation campaigns.
- Align with **CISA KEV catalog** for prioritized coverage.

**Acceptable Values**

| Format | Example |
| :---- | :---- |
| `Vuln: CVE-YYYY-NNNNN` | `Vuln: CVE-2025-24813` |

---

# Threat

Threat: tags associate detections with **named exploits or named campaigns**. These are optional and should only be used when a rule is purpose-built to detect a specific, time-bound threat event \- not general behavioral TTPs.

- `Threat:` tags are **optional**.
- Use only for **named exploits** (e.g., Log4Shell, React2Shell) or **named campaigns** (e.g., SolarWinds).
- Do **not** use for adversary groups (e.g., Scattered Spider) or malware families (e.g., Cobalt Strike) \- coverage for these is achieved through faceted search across Tactic, Domain, Platform, and other tags.

**User-Centric Faceted Search Example**

*"Show me all detections related to Log4Shell."*

Facet filter:

- `Threat: Log4Shell`

**Why not adversary groups or malware?**

A generic behavioral rule may detect TTPs used by many groups and malware families. Tagging individual rules with group or malware names creates an unmaintainable, misleading mapping. Instead, use faceted search to compose coverage queries (e.g., `Tactic: Initial Access` \+ `Domain: Identity` \+ `Platform: Okta` to assess coverage for a group's known TTPs).

**Acceptable Values (Not Exhaustive)**

| Value | Description |
| :---- | :---- |
| `Threat: Log4Shell` | Log4Shell (CVE-2021-44228) exploitation |
| `Threat: React2Shell` | React2Shell server-side exploitation |
| `Threat: SolarWinds` | SolarWinds supply chain campaign |

---

# MITRE Atlas

Mitre Atlas: tags map GenAI/AI-specific detections to **MITRE ATLAS techniques**.

- **Conditional** \- required for rules in the GenAI domain.

**Acceptable Values**

MITRE ATLAS technique IDs (e.g., `Mitre Atlas: T0051`, `Mitre Atlas: T0054`).

---

# Profile

Profile: tags classify a rule's **deployment profile or fidelity characteristics**. These help customers understand the operational trade-offs of enabling a rule and support onboarding workflows.

- `Profile:` tags are **optional** and will be added **incrementally** as rules are evaluated over time.

**User-Centric Faceted Search Example**

*"Show me only high-fidelity detections for initial deployment."*

Facet filter:

- `Profile: High-Fidelity`

**XDR-Centric Use Case**

- Support **phased deployment** (start with high-fidelity, expand to aggressive).
- Enable agentic workflows to recommend rules based on **environment maturity**.

**Acceptable Values**

| Value | Description |
| :---- | :---- |
| `Profile: Recommended` | Suitable for most environments with acceptable noise levels |
| `Profile: Aggressive` | Broad detection, higher expected noise \- for mature SOCs |
| `Profile: High-Fidelity` | Low noise, high confidence \- suitable for automated response |
| `Profile: Compliance` | Compliance-driven detection \- regulatory or audit requirements |
| `Profile: Beta` | Newly added rule under observation \- expected outcome not yet determined. |

---

# Resources

Resources: tags indicate the presence of **supporting documentation or analyst guidance** associated with a rule.

**User-Centric Faceted Search Example**

*"Show me detections that include an investigation guide."*

Facet filter:

- `Resources: Investigation Guide`

**XDR-Centric Use Case**

- Guide analysts toward enriched triage workflows.
- Allow agentic workflows to reference human-readable investigation content.

**Acceptable Values**

| Value | Description |
| :---- | :---- |
| `Resources: Investigation Guide` | Rule includes an investigation guide in the `note` field |
| `Resources: Workflow` | Rule includes an associated [Elastic Workflow](https://www.elastic.co/blog/elastic-workflows-technical-preview) for automated response |
| `Resources: OS Query` | Rule includes an associated [osquery](https://www.elastic.co/docs/solutions/security/investigate/osquery) investigation query |

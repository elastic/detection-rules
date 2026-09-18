# XDR / SIEM Rule Tag Taxonomy

Canonical values are `EXPECTED_RULE_TAGS` in `detection_rules/schemas/definitions.py`.
This file mirrors that list.

| Prefix | Values |
| --- | --- |
| Domain | Cloud, Container, Containers, Email, Endpoint, GenAI, Identity, LLM, Network, OT/IoT, SaaS |
| Platform | AWS, Azure, Entra ID, GCP, GitHub, Google Workspace, Kubernetes, Linux, Microsoft 365, Okta, Windows, Wiz, macOS |
| OS | Linux, Windows, macOS |
| Rule Type | BBR, Custom Query (KQL), ES\|QL, Event Correlation (EQL), Higher-Order, Higher-Order Rule, Indicator Match, ML, Machine Learning, New Terms, Threshold, Threat Match |
| Noise | High, Low, Medium, Unknown |
| Performance | Fast, Normal, Slow, Unknown, Very Slow |
| Profile | Aggressive, Beta, Recommended |
| Resources | Investigation Guide, LLM, OS Query, Workflow |
| Promotion | External Alerts |
| Mitre Atlas | `*` (technique IDs) |
| Use Case | Active Directory Monitoring, Asset Visibility, Configuration Audit, Guided Onboarding, Identity and Access Audit, Log Auditing, Network Security Monitoring, Threat Detection, UEBA, Vulnerability |
| Tactic | Collection, Command and Control, Credential Access, Defense Evasion, Defense Impairment, Discovery, Execution, Exfiltration, Impact, Initial Access, Lateral Movement, Persistence, Privilege Escalation, Reconnaissance, Resource Development, Stealth |

**Data Source:** APM, AWS, AWS Bedrock, AWS CloudTrail, AWS Sign-In, AWS VPC Flow Logs, Active Directory, Amazon Web Services, Auditd Manager, Azure, Azure Activity Logs, Azure OpenAI, Azure Platform Logs, Check Point Harmony Email Logs, CrowdStrike Falcon, Crowdstrike, CyberArk PAS, Elastic Defend, Elastic Defend for Containers, Elastic Endgame, Entra ID Audit Logs, Entra ID Protection Logs, Entra ID Sign-In, Entra ID Sign-In Logs, File Integrity Monitoring, Fortinet, GCP, GitHub Code Scanning Logs, Github, Google Cloud Platform, Google SecOps, Google Workspace, Google Workspace User Log Events, Jamf Protect, Kubernetes, macOS Security Events, Microsoft 365, Microsoft Defender XDR, Microsoft Defender for Cloud Alerts, Microsoft Defender for Identity, Microsoft Defender for Office 365, Microsoft Entra ID Sign-In Logs, Microsoft Exchange Online Logs, Microsoft Graph, Microsoft Purview, Microsoft Sentinel, Network Packet Capture, Network Traffic, Okta, PAN-OS, PowerShell Logs, Rapid7 Threat Command, SentinelOne, SonicWall, Splunk, Suricata, Sysmon, Windows Security Event Logs, Windows System Event Logs, Wiz, Zoom

**Service:** AWS Backup, AWS Bedrock, AWS CloudFormation, AWS CloudWatch, AWS Config, AWS Detective, AWS DynamoDB, AWS EC2, AWS EFS, AWS EKS, AWS EventBridge, AWS GuardDuty, AWS IAM, AWS KMS, AWS Lambda, AWS Organizations, AWS RDS, AWS Route 53, AWS S3, AWS SES, AWS Sign-In, AWS SNS, AWS SQS, AWS SSM, AWS STS, AWS Secrets Manager, AWS WAF, AWS Security Hub, Apache HTTP Server, Apache Tomcat, Azure Event Hubs, Azure Functions, Azure Key Vault, Azure OpenAI, Azure Storage, GCP BigQuery, GCP Cloud Functions, GCP Cloud Storage, GCP Compute Engine, GCP Secret Manager, GitHub Actions, GitHub Code Scanning, IIS, Microsoft Exchange Online, Microsoft OneDrive, Microsoft Purview, Microsoft SharePoint, Microsoft Teams, Nginx

**Threat:** AiTM Phishing, BPFDoor, Browser Extension Abuse, Brute Force, ClickFix, Cloud VM Execution, Cobalt Strike, Container Escape, Cryptomining, Device Code Phishing, DLL Side-Load, Download Tool Abuse, Dynamic DNS, Encoding-Based Obfuscation, IMDS Credential Theft, Impossible Travel, Information Stealer, Installer Abuse, Lightning Framework, Living off the Land, LLMjacking, LNK/Shortcut Abuse, Log4Shell, Masquerading, OAuth App Consent, Orbit, Protocol Tunneling, Ransomware, React2Shell, Remote Management Tool Abuse, Reverse Shell, Rootkit, Script-Based Execution, Supply Chain, Suspicious TLD, TripleCross, Unauthorized AI Usage, Vulnerability Exploit, Vulnerable Driver, Web Application Attack, Web Service Abuse, Web Shell, WebDAV Abuse

**Vuln:** `CVE-*` entries listed in `EXPECTED_RULE_TAGS`.

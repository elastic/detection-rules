# LLM Threat Hunting Queries

Welcome to the `LLM` subfolder within the `hunting` directory of the `detection-rules` repository. This specialized section is dedicated to threat hunting queries designed for Large Language Model (LLM) applications, targeting the unique security challenges these systems face.

## Emphasis on OWASP Top 10 for LLMs

Our queries are developed with a keen awareness of the [OWASP Top 10 risks for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/). This crucial resource outlines the predominant security risks for LLMs, guiding our efforts in crafting queries that proactively address these vulnerabilities and ensure comprehensive threat mitigation.

## Emphasis on MITRE ATLAS

The [ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS/) covers the progression of tactics used in attacks with ML techniques belonging to different tactics.

- Reconnaissance
- Resource Development
- Initial Access
- ML Model Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Collection
- ML Attack Staging
- Exfiltration
- Impact

## Scope of Threats and Protections

The queries in this folder are tailored to monitor and protect against a broad spectrum of threats to LLMs:

- **Sensitive Content Refusal**: Monitors LLM interactions to ensure compliance with ethical standards, particularly in refusing to process sensitive topics.
- **Denial of Service (DoS) and Resource Exhaustion**: Aims to prevent disruptions in LLM operations by detecting patterns indicative of DoS attacks or resource exhaustion scenarios.
- **Latency Anomalies**: Tracks processing delays that could signal underlying performance issues or security threats, maintaining operational efficiency and safeguarding against potential attacks like DDoS.

### Benefits of These Queries

These queries assist organizations in:
- Detecting and mitigating misuse or attacks that threaten data integrity or disrupt services.
- Ensuring that LLMs adhere strictly to operational and ethical boundaries through continuous monitoring.
- Maintaining high performance and reliability of LLMs by preemptively identifying and resolving factors that cause inefficiencies.

For more details, read our blog on [LLM Detections](https://www.elastic.co/security-labs/elastic-advances-llm-security).
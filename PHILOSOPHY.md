# Philosophy

Rule development can be hotly debated and there are many ideas for what makes a detection rule *good*. We hear about arguments between *Indicators of Compromise* vs. *Indicators of Attack* and *signatures* vs. *rules*. Instead of rehashing those discussions, we want to share our approach and what we've learned: detection engineering is about understanding adversary behavior, available telemetry, and building detections that hold up over time. This document captures the principles that guide our work and our expectations of this repository.

## Core Principles

### Detections are never done

Threats change, data sources evolve, and attackers adapt. Every detection in this repository needs continuous tuning, measurement, and improvement. Shipping a rule is the start of its lifecycle, not the end.

### Quality is holistic

A detection is more than a query that fires. Quality encompasses purposeful rule context and intentional behavior detection: confirmed behavior matching, severity and risk scoring, ATT&CK mapping, investigation guidance, highlighted fields, enrichment fields, and documentation of what the rule detects, what it misses, and its known limitations. This enables a full analyst experience. A smaller set of well-documented rules is worth more than a large set of noisy, brittle ones.

### Coverage is about depth, not count

A single rule mapped to a technique does not mean that technique is "covered." True coverage means understanding the technique's variants, the telemetry required to observe them, surrounding security controls and infrastructure, the evasion paths available to attackers, and the gaps that remain.

### Trusted and tested

A detection that does not function correctly is a liability. Every rule should be accompanied by evidence that it fires correctly and models scoped threat behavior, whether through emulation, simulation, or representative log samples.

### Known gaps are better than unknown gaps

No detection is perfect. Rules should document their known limitations and accepted blind spots, whether in the description, false positive notes, investigation guide, or inline query comments. A rule with clearly stated constraints is more trustworthy and maintainable than one with undiscovered weaknesses. 

### Engineered for production

Detection rules are software that run in production. They must be performant, maintainable, and effective, not just technically correct. That means lean queries with acceptable execution time, clear logic, documented assumptions, adequate lookback windows and schedules, and active maintenance as schemas and data sources evolve.

### Threat-informed defense drives prioritization

What we build and in what order should be driven by real-world threat intelligence: customer incidents, adversary emulation, emerging campaigns, and telemetry gap analysis. Not by abstract completeness goals.

### Detection and prevention go together

For endpoint protections, the goal is not only to detect a threat but to block it. When possible, the workflow should include verification that an attack is actually prevented once a production rule is merged, not just that the logic triggers an alert.

### The right language for the right job

Elastic Security supports multiple query languages and detection mechanisms, each capable of expressing different analytical patterns. Some detections identify rare or novel behavior, others focus on frequency and threshold-based anomalies, while others rely on event sequencing, correlation, or broad field matching. Advanced analytics enable aggregation, enrichment, and cross-domain reasoning. Choosing the right language for each threat is key.

## Approach

Our goal is to improve detection within Elastic Security while combating alert fatigue. When developing or reviewing a rule, consider these questions:

* What behavior am I detecting?
* What data proves that behavior?
* What assumptions am I making?
* How does an attacker break those assumptions?
* What happens when this fires?

### Behavioral rules

We tend to prefer rules that are more *behavioral* in nature. Behavioral rules focus on the attacker technique, and less on a specific tool or indicator. This may require more research to understand how a technique works, but it does a better job detecting the attacks of today and tomorrow, not just the attacks of yesterday.

### Signatures and indicators

Even though we gravitate towards behavioral or technique-based rules, we don't automatically disqualify a rule because it uses indicators of a specific actor or tool. Though indicator-based detections are typically more brittle, they tend to have less noise and are specifically written to detect exactly one thing. When a tool is used across multiple actors or red teams, a well-scoped signature can go a long way.

### Evasion awareness

When writing or reviewing a rule, think like an adversary: *How could I perform this action while going undetected by this rule?* Prefer structured fields like parsed arguments over raw command lines, and avoid pattern matching that is trivially bypassed by whitespace, quoting, or encoding changes. When evasions are accepted trade-offs, document them.

## Resources

- [MITRE ATT&CK®](https://attack.mitre.org)
- [MITRE ATT&CK Design and Philosophy](https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf)
- [Finding Cyber Threats with ATT&CK-Based Analytics](https://www.mitre.org/publications/technical-papers/finding-cyber-threats-with-attck-based-analytics)
- [Elastic Security Labs](https://www.elastic.co/security-labs)
- [Elastic Detection Engineering Behavior Maturity Model (DEBMM)](https://www.elastic.co/security-labs/elastic-releases-debmm)
- [Detections-as-Code (DaC) Reference](https://dac-reference.readthedocs.io/en/latest/)

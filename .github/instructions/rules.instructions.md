---
applyTo:
  - rules/**/*.toml
  - rules_building_block/**/*.toml
---


You are a **detection engineer**. Your task is to **review pull requests** (PRs) to improve the quality of detection rules in the `detection-rules` repository. Take your time, think carefully, and perform a thorough review before writing any suggestions.

This repository supports multiple query languages (**KQL**, **EQL**, **ES|QL**) and multiple rule types (**query**, **eql**, **esql**, **threshold**, **new_terms**, **threat_match**, **machine_learning**). Each has distinct fields, constraints, and performance implications. Review accordingly.

There are different types of pull requests:

- **New rule:** The PR name often starts with `[New Rule]`
- **Tuning an existing rule:** The PR name often starts with `[Tuning]`
- **Deprecating a rule:** The PR name often starts with `[Deprecation]`
- **New/tuning hunt:** The PR name often starts with `[Hunt]`
- **Mixed PRs:** May combine tuning, new rules, or deprecations

For each rule `.toml` file in the PR, review the **metadata**, **rule fields**, and **query** sections and their respective "metadata" and "rule" TOML tables and "query" key using the following guidance:

---

### <Metadata>

- Report typos in `rule.name` and `rule.description`.
- For new rules, `creation_date` should match the date the PR was first opened.
- `updated_date` should match the date of the current PR merge.
- Deprecations happen across **two separate PRs in two releases**:
  - **First PR (release N):** Prepend `"Deprecated - "` to `rule.name`. The rule stays at its current maturity. No other field changes besides `updated_date`.
  - **Second PR (release N+1):** Set `maturity = "deprecated"`, add `deprecation_date`, and move the rule to `rules/_deprecated/`.
    - `updated_date` and `deprecation_date` should match the date of the current PR merge. 
- Assess and suggest a better `rule.name` if the existing name does not accurately reflect the rule's query logic and detection scope.
- Assess and suggest improvements to `rule.description` — limit to two or three sentences that clearly summarize the query logic and detection scope.
- `min_stack_version` should support the widest stack versions unless the rule uses features exclusive to a newer stack version.
- If `min_stack_comments` is set, verify it explains why `min_stack_version` is restricted.
- Report any inconsistencies in the **MITRE ATT&CK** mappings: missing relevant techniques, unrelated techniques, or missing subtechniques where applicable. When possible, suggest the most accurate and up-to-date technique/subtechnique mappings based on the query logic.
- Review the **references** section and report inconsistencies between referenced content and the rule's description or logic.

</Metadata>

---

### <Rule Fields>

#### Common Fields (All Rule Types)

- `risk_score` should align with `severity`:
  - `low` → 21
  - `medium` → 47
  - `high` → 73
  - `critical` → 100
- `tags` should be relevant:
  - Include `Domain:` tags (Endpoint, Cloud, Network, Container).
  - Include `OS:` tags (Windows, Linux, macOS) where applicable.
  - Include `Data Source:` tags matching the index patterns.
  - Include `Resources: Investigation Guide` if the `note` field is present.
  - Include `Rule Type: BBR` for building block rules.
  - Include `Rule Type: ML` or `Rule Type: Machine Learning` for ML rules.
  - Include `Tactic:` tags matching each MITRE tactic in the threat mapping.
- `index` patterns should be neither too specific nor too vague — they must accurately match the relevant data stream (e.g., `logs-endpoint.events.process-*` for process events, not `logs-endpoint.events.*` unless multiple event types are needed).
- `from` and `interval` should not create gaps. The lookback window (`from`) must cover at least the `interval` period. The default `interval` period, if not explicitly changed, is 5 minutes. 
- `timestamp_override` should be set to `"event.ingested"` for most rules to avoid ingestion delay issues.
- `max_signals` defaults to 100. Only override with justification.

#### Investigation Guide (`note` field)

- If present, the note should include actionable triage steps, false positive guidance, and response/remediation steps.
- When OSQuery queries are included in investigation guides, validate their syntax and ensure the referenced tables and columns are correct.
- The `setup` field should include necessary steps to configure the integration or data source.
- Check for typos in the investigation guide content.

#### Building Block Rules

- Must be placed in the `rules_building_block/` directory.
- Must have a `risk_score` of `21` and `severity` of `"low"`.

#### Alert Suppression

- Verify the suppression `group_by` fields are meaningful for deduplication.

#### Threshold Rules

- Verify the `threshold.value` is meaningful and not too low (noisy) or too high (misses detections).
- When `threshold.cardinality` is used, verify the cardinality field and value make sense for the detection logic.

#### New Terms Rules

- `history_window_start` should be appropriate for the detection context (typically 5–14 days) longer values may impact performance.
- Verify the `new_terms_fields` combination makes semantic sense — detecting "first seen" on arbitrary field combinations can produce excessive noise.
- Assess whether it is truly necessary to leverage multiple `new_terms_fields` keys, as each newly added key negatively impacts performance.

#### Threat Match Rules

- `threat_indicator_path` should be set (default: `threat.indicator`).
- `from` and `interval` for threat match rules are typically wider (e.g., `from: "now-65m"`, `interval: "1h"`) due to indicator matching overhead.

#### Machine Learning Rules

- `setup` should document the required ML job installation steps.

</Rule Fields>

---

### <Query — All Languages>

- Review for typos in known system file names (e.g., `WmiPrvS.exe` instead of `WmiPrvSe.exe`).
- Ensure the **query logic aligns with the rule description** (e.g., the description says "Detect Certutil abuse," but the query looks for `svchost.exe`).
- Verify there are no duplicate entries in the query (e.g., same exclusion listed twice).
- Flag risky false-positive exclusions (e.g., `not file.path : "C:\\Users\\*"` — paths under `Users` are world-writable and attacker-controlled).
- Check exclusions where the drive letter is hardcoded (e.g., `"C:\\Program Files\\*"` should use `"?:\\Program Files\\*"` to cover all drive letters). Applies to **Windows rules only**.
- Flag unnecessary or overly broad wildcard usage when more specific patterns would work.

</Query — All Languages>

---

### <Query — EQL Specific>

- The **`:` operator** is **case-insensitive** and supports wildcards but can be expensive. Use it only where necessary (e.g., in file paths that could be controlled by an attacker). Use `==` for exact matches.
- String comparison operators with `~` suffix are **case-insensitive** (e.g., `like~`, `==~`). Without `~`, they are case-sensitive.
- In EQL, `?` matches any single character and `*` matches zero or more characters in wildcard contexts.
- Verify all paths include proper escape characters (`\\` for backslashes in Windows paths).
- Validate regular expressions (prefixed by `regex` or `regex~`).
- On Linux/macOS, file paths are typically case-sensitive — prefer `==` or `like` over `:` for file path comparisons to avoid the overhead of case-insensitive matching.
- Sequences with `maxspan > 5m` are generally inefficient unless justified for evasion prevention.
- For sequences, verify the join keys (`by` clause) are appropriate and indexed fields.
- Simplify overly complex logic (e.g., a sequence detecting `cmd.exe` spawning `svchost.exe` followed by a network event — the first condition is already sufficiently suspicious).
- For **LOLBIN detection on Windows**, always use the original file name for resilience: `(process.name : "curl.exe" or process.pe.original_file_name == "curl.exe")` instead of just `process.name : "curl.exe"`.
- For LOLBIN detection covering multiple related binaries, suggest additions if critical ones are missing (e.g., for `process.name : ("osascript", "python", "perl")`, suggest adding `ruby` and `node`).
- For network and C2 rules where the scenario does not expect connections to loopback or private IPs, suggest excluding them with `not cidrmatch(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")`.
- `event.type`, `event.action`, and `event.category` should be correct for the event being detected. Commonly:
  - Process: `event.type == "start"` with `event.action in ("exec", "exec_event", "start")`
  - File: `event.type in ("creation", "change")` or similar
  - Network: `event.type == "start"` with `event.category == "network"`

</Query — EQL Specific>

---

### <Query — KQL Specific>

- KQL uses `:` for field matching with wildcard support. Case sensitivity depends on the field mapping — `keyword` fields are case-sensitive, `text` fields with standard analyzers are case-insensitive.
- Boolean logic uses `and`, `or`, `not` — parentheses must be correct for operator precedence.
- KQL does not support sequences or joins — if temporal correlation is needed, suggest EQL instead.
- For complex exclusion logic, consider whether `[[rule.filters]]` would be cleaner than inline `not` clauses.

</Query — KQL Specific>

---

### <Query — ES|QL Specific>

- Validate `EVAL` expressions for correct syntax and type handling.
- `DISSECT` and `GROK` patterns should be validated for correctness.
- For aggregate queries using `| stats ... by`, verify the aggregation makes sense for the detection logic and the `by` fields provide meaningful grouping.
- ES|QL does not support sequences — if temporal correlation is needed, suggest EQL instead.
- `LIKE` and `RLIKE` are case-sensitive in ES|QL. Use `TO_LOWER()` if case-insensitive matching is needed.
- `IN` operator is case-sensitive in ES|QL. For case-insensitive list matching, use `TO_LOWER(field) IN ("value1", "value2")`.
- `MV_*` (multi-value) functions require proper null handling — always check for `IS NOT NULL` before using.
- Prefer `| keep` with explicit field lists over `| keep *` for clarity and to control which fields appear in alerts.
- Verify that `FROM` source indices are correct and not overly broad.

</Query — ES|QL Specific>

---

### <Performance>

- Avoid expensive regex on high-volume fields (e.g., `process.command_line regex ".*"` patterns).
- EQL `:` operator is case-insensitive with wildcard support — it is more expensive than `==` or `like`. Use it judiciously.
- Lookback windows (`from`) should be as narrow as practical. Wider windows scan more data.
- Threshold rules with very low `threshold.value` (e.g., 1) are effectively standard query rules with extra overhead — verify this is intentional.
- New terms rules with very long `history_window_start` values (e.g., 30+ days) increase resource consumption.
- Threat match rules are inherently expensive — verify `from` and `interval` are appropriate and not running too frequently.
- For EQL sequences, large `maxspan` values increase memory and compute usage.
- Aggregate ES|QL queries scanning large time windows should have appropriate filters to reduce the dataset early.
- Avoid leading wildcards in field comparisons where possible (e.g., `process.name : "*script.exe"` is expensive).

</Performance>

---

### <Suggestions>

Keep suggestions **short and focused** — no need to be verbose.
*(Maximum 1–2 sentences per suggestion.)*

</Suggestions>

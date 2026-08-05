# XDR / SIEM Rule Tag Taxonomy

Governed `Category: Value` tags for prebuilt detection rules. Used by Copilot PR review
(`.github/instructions/rules.instructions.md`), Kibana faceted search, and agentic workflows.

Unit tests today enforce a subset of required tags and allowed prefixes via
`EXPECTED_RULE_TAGS` in `detection_rules/schemas/definitions.py`. Full required-tag
enforcement for the new categories is intentionally deferred.

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

## Platform examples

`AWS`, `Azure`, `Entra ID`, `GCP`, `Google Workspace`, `Microsoft 365`, `Okta`,
`GitHub`, `Kubernetes`, `Windows`, `Linux`, `macOS`, `Elastic`, `Wiz`, `FortiGate`.

## Data Source guidance

Prefer the concrete telemetry name (`AWS CloudTrail`, `Entra ID Sign-in Logs`,
`Elastic Defend`) over the vendor alone. Preserve any dual/legacy tags still required
by index-based unit tests (for example AWS rules still need both `Data Source: AWS` and
`Data Source: Amazon Web Services`). Match existing rule casing during migration
(e.g. `Sign-in`, not `Sign-In`); do not add new Data Source spellings to
`EXPECTED_RULE_TAGS` until outliers are normalized.

## Service guidance

Optional but recommended when the rule targets a specific component. Prefix cloud
services with the vendor (`AWS S3`, `Azure Key Vault`). Web/app servers generally need
no vendor prefix (`IIS`, `Nginx`, `Apache Tomcat`).

## Rule Type mapping

| Rule `type` / case | Tag(s) |
| --- | --- |
| `esql` | `Rule Type: ESQL` |
| `query` (KQL) | `Rule Type: Custom Query (KQL)` |
| `eql` | `Rule Type: Event Correlation (EQL)` |
| `threat_match` | `Rule Type: Indicator Match` |
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

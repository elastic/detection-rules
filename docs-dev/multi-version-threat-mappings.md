# Multi-version threat mappings (MITRE ATT&CK v18 / v19 / …)

A rule's MITRE ATT&CK mapping lives in its `threat` field, which is shipped verbatim to Kibana. To
support more than one ATT&CK version (or, in future, other frameworks) at once, a rule can also carry
additional, version-tagged mappings in a `threat_mappings` field. These are **repo-side only** — the
build selects exactly one mapping to emit as the API `threat` and strips `threat_mappings` from the
shipped artifact.

This makes it possible to author and review a v19 mapping today, while continuing to ship v18, and to
flip the shipped version later with a single config/env change.

## Rule schema

`threat` continues to hold the **baseline** mapping (MITRE ATT&CK v18). Additional versions are added
as `threat_mappings` entries, each keeping the same structure as `threat` plus a `framework` and a
`version`:

```toml
[[rule.threat]]                       # baseline (v18) — shipped by default, consumed by Kibana
framework = "MITRE ATT&CK"
  [[rule.threat.technique]]
  id = "T1078"
  name = "Valid Accounts"
  reference = "https://attack.mitre.org/techniques/T1078/"
  [rule.threat.tactic]
  id = "TA0001"
  name = "Initial Access"
  reference = "https://attack.mitre.org/tactics/TA0001/"

[[rule.threat_mappings]]              # additional, version-tagged mapping (repo-side only)
framework = "MITRE ATT&CK"
version = "19"
  [[rule.threat_mappings.threat]]
  framework = "MITRE ATT&CK"
  # ...same tactic/technique/subtechnique structure as `threat`...
```

Validation enforces unique `(framework, version)` blocks and that each inner threat entry's framework
matches its wrapper.

## Selecting which version is shipped

At build time (`TOMLRuleContents.to_api_format`), the configured framework/version is emitted as
`threat`:

- Default is the baseline `(MITRE ATT&CK, 18)` — `threat` is emitted unchanged.
- When another version is configured, the matching `threat_mappings` block is emitted as `threat`.
- If a rule has no block for the requested version, its baseline `threat` is emitted (with a warning),
  so packaging never breaks.
- `threat_mappings` is always stripped from the API output.

Set the output version with either config keys or environment variables (env takes precedence):

```yaml
# _config.yaml
threat_mapping_framework: "MITRE ATT&CK"
threat_mapping_version: "19"
```

```bash
DR_THREAT_MAPPING_FRAMEWORK="MITRE ATT&CK" DR_THREAT_MAPPING_VERSION=19 python -m detection_rules ...
```

Because the field is stripped from the API format, adding `threat_mappings` to rules does **not**
change rule hashes or trigger version bumps until the output version is actually flipped.

## Generating a target-version mapping

`dev attack convert-threat-mappings` does a first-pass generation of a target-version mapping from a
rule's source mapping. It is **accuracy-first**: any source tactic/technique/subtechnique that is not
explicitly present in the mapping config is **dropped rather than guessed**, and every dropped item is
reported for review.

```bash
# preview the v18 -> v19 conversion for all rules
python -m detection_rules dev attack convert-threat-mappings -t 19 --dry-run

# write the v19 blocks (scope with -d/--directory, -f/--rule-file, -id/--rule-id)
python -m detection_rules dev attack convert-threat-mappings -t 19 -d rules/

# use an explicit mapping config instead of the configured directory
python -m detection_rules dev attack convert-threat-mappings -t 19 --config path/to/map.yaml
```

## Mapping config format

Conversion is driven by a **directory of per-pair config files** (default
`detection_rules/etc/attack-version-maps/`). Each file declares one `(framework, source_version ->
target_version)` triple and is **self-contained** — it carries the destination `id`, `name`, and
`reference` for each source id. A source id mapped to `null`, or absent entirely, is dropped.

```yaml
framework: "MITRE ATT&CK"
source_version: "18"
target_version: "19"
tactics:
  TA0001: { id: TA0001, name: Initial Access, reference: "https://attack.mitre.org/tactics/TA0001/" }
techniques:
  T1078: { id: T1078, name: "Valid Accounts", reference: "https://attack.mitre.org/techniques/T1078/" }
  T1100: null        # explicitly dropped (deprecated / no confident target)
subtechniques:
  T1078.004: { id: T1078.004, name: "Cloud Accounts", reference: "https://attack.mitre.org/techniques/T1078/004/" }
```

Adding a new destination (e.g. v19 -> v20, or another framework) is just a new file declaring its own
triple. Multiple destinations coexist as separate `threat_mappings` blocks per rule.

### Scaffolding a config

Because the config is self-contained, `dev attack scaffold-version-map` generates an **identity**
baseline from the currently loaded ATT&CK data (every non-revoked/non-deprecated id maps to itself).
Review and curate it against the target version's real changes (renames, deprecations, splits) before
relying on it:

```bash
python -m detection_rules dev attack scaffold-version-map -t 19 -o detection_rules/etc/attack-version-maps/attack_v18_to_v19.yaml
```

## Detections-as-Code (custom rules)

All of the above is DaC-aware. With `CUSTOM_RULES_DIR` set, the commands operate on the custom rule
directories automatically. Point a custom rules repo at its own mapping configs via the custom
`_config.yaml`:

```yaml
attack_version_maps_dir: etc/attack-version-maps   # relative to the custom _config.yaml
```

or pass `--config` explicitly. The output-selection keys/env vars work the same way for custom rules.

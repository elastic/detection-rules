# Feature Parity Analysis

This document reviews several CLI functions and compares their feature sets to the `kibana import-rules` and `kibana export-rules` commands. The goal is to identify where it may be useful to extend other commands with similar flags or configuration support.

## `create-rule`
- **Change:** Added `--strip-dates` and `--strip-version` options that default to repository configuration, so new rules honor `_config.yaml` settings for timestamp and version removal【F:detection_rules/main.py†L84-L107】【F:detection_rules/cli_utils.py†L169-L176】.

## `custom-rules`
- **Change:** `custom-rules setup-config` now writes `_config.yaml` with `no_tactic_filename`, `strip_version`, `strip_dates`, `strip_exception_list_id`, and `default_author` keys so new repositories reflect the latest options【F:detection_rules/custom_rules.py†L31-L44】.

## `import-rules-to-repo`
- **Change:** Added `--strip-version` option and enabled honoring `_config.yaml` for stripping dates, versions, and exception IDs; verified importing a Kibana-exported rule removes metadata and applies a default author【F:detection_rules/main.py†L144-L210】【F:rules-test/external-rule/test_rule_uuid_export.ndjson†L1-L14】.

## `export-rules-from-repo`
- **Current behavior:** Exports repository rules to NDJSON, with optional metadata and inclusion of action connectors or exceptions【F:detection_rules/main.py†L540-L582】.
- **Missing parity features:** `kibana import-rules` offers flags for overwriting assets and excluding specific exception lists during import【F:detection_rules/kbwrap.py†L107-L139】. Overwrite semantics do not apply at export time, but there is no way to omit selected exception lists from the generated NDJSON.
- **Suggestion:** Consider a lightweight `--exclude-exceptions` filter for symmetry with Kibana's import command. Value lists and timeline templates remain out of scope for now as noted.

## `mass-update`
- **Current behavior:** Modifies specified fields across matching rules, then validates and saves them【F:detection_rules/main.py†L422-L455】.
- **Recommendation:** Saving uses existing rule contents, so it does not reintroduce stripped dates or version fields. No additional flags appear necessary.

---
This analysis highlights areas where extending command options or config awareness could align the broader CLI with enhancements made to Kibana import/export workflows.

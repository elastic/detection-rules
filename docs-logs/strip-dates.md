# Strip Dates Option

A new `strip_dates` flag was added to the rule export workflow. When enabled via the
`--strip-dates` command line option or the `strip_dates` field in `_config.yaml`,
`creation_date` and `updated_date` are removed before writing the rule TOML.
The metadata removal now occurs before the rule object is serialized, similar to
the `strip_version` implementation. `from_rule_resource` accepts `None` for the
date fields so they are completely omitted and `save_toml` no longer needs a
`strip_dates` argument. The flag is also available on `import-rules-to-repo` to
strip dates when creating local rules from exports.
This helps avoid noisy diffs when exporting rules from Kibana and re-importing
them across clusters.


# Default Author Config

The `import-rules-to-repo` and `kibana export-rules` commands now honor a
`default_author` field in `_config.yaml`. This provides the same behavior as the
`--default-author`/`-da` flag, allowing a default author to be supplied without
specifying the flag on every invocation. The configuration is loaded into
`RULES_CONFIG` and used whenever a rule lacks an `author` value.


# Optional directory flag for Kibana commands

The `kibana import-rules` and `kibana export-rules` commands now treat the `-d/--directory` option as optional. When the option is not provided, the commands fall back to the first entry in the `rule_dirs` array defined in `_config.yaml`. Other commands that rely on the shared `multi_collection` helper—such as `kibana upload-rule` and `export-rules-from-repo`—also use this fallback.

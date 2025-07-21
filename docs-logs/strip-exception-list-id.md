# Strip Exception List IDs

The `--strip-exception-list-id` option on `export-rules` and `import-rules-to-repo` removes the `id` field from each entry in `exceptions_list` blocks. Only the `list_id` is required to reference an existing exception list. This prevents noisy diffs when exporting rules and allows importing them back without errors. A corresponding `strip_exception_list_id` field is available in `_config.yaml` for the export command.

# Strip Dates for Exceptions and Action Connectors

The `--strip-dates` option on `export-rules` and `import-rules-to-repo` now also
removes `creation_date` and `updated_date` from exported exception lists and
action connector files.  Their metadata dataclasses were updated to accept
`None` values so that rules can be imported back without errors.

# Import rules by rule name

## Summary
- Added `--rule-name` option to `kibana import-rules` allowing selection of rules by `rule.name` instead of filename.
- Supports multiple names and Unix-shell style wildcards in a case-insensitive manner.

## Implementation Details
- Extended `multi_collection` helper to accept a new `--rule-name/-rn` option and to filter loaded rules using compiled
  `fnmatch` patterns.
- Added validation to prevent using `--rule-id` and `--rule-name` together and updated default directory resolution to
  include the new flag.
- Updated CLI documentation and help text to describe the new option.

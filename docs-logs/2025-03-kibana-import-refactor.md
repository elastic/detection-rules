# Kibana import-rules refactor

## Summary
Refactored the `kibana import-rules` command to a modular architecture and
updated related helpers.  The new flow imports value lists, exception lists,
timeline templates and rules in clearly separated phases and prints
human-readable log messages (`name - id - message`).  `RuleResource.import_rules`
now returns `RuleResource` objects for successful imports to simplify
consumers.

## Implementation Notes
- Updated `lib/kibana/kibana/resources.py` to change the return signature of
  `RuleResource.import_rules`.
- Rewrote `detection_rules/kbwrap.py` with a five phase import pipeline and
  detailed comments for each step.
- Added `_suggest_reimport` helper to keep previous guidance for transient
  Kibana API errors.
- Adjusted logging to show both resource names and identifiers.

## Files
- `detection_rules/kbwrap.py`
- `lib/kibana/kibana/resources.py`
- `report.md`


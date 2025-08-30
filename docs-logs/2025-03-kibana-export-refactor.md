# Kibana Export Refactor

## Summary
- improve `kibana export-rules` logging using shared `ItemLog`
- report saved and skipped items using `name - id` format

## Implementation Details
- added `ItemLog` helper and per-resource log collection in `detection_rules/kbwrap.py`
- adjusted loops saving rules, exceptions, value lists, timeline templates and action connectors to capture successes and failures
- final summary prints grouped lists for each resource type

# Timeline Template TOML Support

## Summary
- Added dedicated `timeline.py` module with dataclasses allowing timeline templates to be handled like rules, exception lists and action connectors.
- Extended the generic loader and `kibana` CLI helpers to read and write timeline templates in TOML format.

## Testing
- `CUSTOM_RULES_DIR=./rules-test pytest tests/test_timeline_templates.py`
- Manual import and export using the `kibana` CLI against a test space including timeline templates.

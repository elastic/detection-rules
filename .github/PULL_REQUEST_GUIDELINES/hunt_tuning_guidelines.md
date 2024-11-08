## Hunt: Tuning - Guidelines

These guidelines serve as a reminder set of considerations when tuning an existing Hunt.

### Documentation and Context

- [ ] Detailed description of the suggested changes.
- [ ] Provide example JSON data or screenshots.
- [ ] Evidence of enhancing hunting results by either reducing false-positives or removing false-negatives.
- [ ] Evidence of specific environment factors influencing customized hunt tuning (Contextual Tuning).
- [ ] Evidence of refining hunts to better detect deviations from typical behavior (Behavioral Tuning).
- [ ] Field Usage: Ensure standardized fields for compatibility across different data environments and sources.

### Hunt Metadata Checks

- [ ] `author`: The name of the individual or organization authoring the rule.
- [ ] `name` and `description` are descriptive and typo-free.
- [ ] `language`: The query language(s) used in the rule, such as `KQL`, `EQL`, `ES|QL`, `OsQuery`, or `YARA`.
- [ ] `query` is inclusive, not overly exclusive. Review to ensure the original intent of the hunt is maintained.
- [ ] `integration` aligns with the `index`. Ensure updates if the integration is newly introduced.
- [ ] `notes` includes additional information (e.g., Triage and analysis investigation guides, timeline templates).
- [ ] `mitre` matches appropriate technique and sub-technique IDs that hunting query collect's data for.
- [ ] `references` are valid URL links that include information relevenat to the hunt or threat.

### Testing and Validation

- [ ] Evidence of testing and valid query usage.
- [ ] Markdown Generated: Run `python -m hunting generate-markdown` with specific parameters to ensure a markdown version of the hunting TOML files is created.
- [ ] Index Refreshed: Run `python -m hunting refresh-index` to refresh indexes.
- [ ] Run Unit Tests: Run `pytest tests/test_hunt_data.py` to run unit tests.

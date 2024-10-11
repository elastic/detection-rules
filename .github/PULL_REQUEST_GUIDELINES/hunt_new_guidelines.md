## Hunt: New - Guidelines

Welcome to the `hunting` folder within the `detection-rules` repository! This directory houses a curated collection of threat hunting queries designed to enhance security monitoring and threat detection capabilities using the Elastic Stack.

### Documentation and Context

- [ ] Detailed description of the Hunt.
- [ ] Link related issues or PRs.
- [ ] Include references.
- [ ] Field Usage: Ensure standardized fields for compatibility across different data environments and sources.

### Hunt Metadata Checks

- [ ] `author`: The name of the individual or organization authoring the rule.
- [ ] `uuid`: Unique UUID.
- [ ] `name` and `description` are descriptive and typo-free.
- [ ] `language`: The query language(s) used in the rule, such as `KQL`, `EQL`, `ES|QL`, `OsQuery`, or `YARA`.
- [ ] `query` is inclusive, not overly exclusive, considering performance for diverse environments.
- [ ] `integration` aligns with the `index`. Ensure updates if the integration is newly introduced.
- [ ] `notes` includes additional information regarding data collected from the hunting query.
- [ ] `mitre` matches appropriate technique and sub-technique IDs that hunting query collect's data for.
- [ ] `references` are valid URL links that include information relevenat to the hunt or threat.
- [ ] `license`

### Testing and Validation

- [ ] Evidence of testing and valid query usage.
- [ ] Markdown Generated: Run `python -m hunting generate-markdown` with specific parameters to ensure a markdown version of the hunting TOML files is created.
- [ ] Index Refreshed: Run `python -m hunting refresh-index` to refresh indexes.
- [ ] Run Unit Tests: Run `pytest tests/test_hunt_data.py` to run unit tests.

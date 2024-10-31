## Enhancement - Guidelines

These guidelines serve as a reminder set of considerations when addressing adding a new schema feature to the code.

### Documentation and Context

- [ ] Describe the feature enhancement in detail (alternative solutions, description of the solution, etc.) if not already documented in an issue.
- [ ] Include additional context or screenshots.
- [ ] Ensure the enhancement includes necessary updates to the documentation and versioning.

### Code Standards and Practices

- [ ] Code follows established design patterns within the repo and avoids duplication.
- [ ] Code changes do not introduce new warnings or errors.
- [ ] Variables and functions are well-named and descriptive.
- [ ] Any unnecessary / commented-out code is removed.
- [ ] Ensure that the code is modular and reusable where applicable.
- [ ] Check for proper exception handling and messaging.

### Testing

- [ ] New unit tests have been added to cover the enhancement.
- [ ] Existing unit tests have been updated to reflect the changes.
- [ ] Provide evidence of testing and validating the enhancement (e.g., test logs, screenshots).
- [ ] Validate that any rules affected by the enhancement are correctly updated.
- [ ] Ensure that performance is not negatively impacted by the changes.
- [ ] Verify that any release artifacts are properly generated and tested.

### Additional Schema Related Checks

- [ ] Ensure that the enhancement does not break existing functionality. (e.g., run `make test-cli`)
- [ ] Review the enhancement with a peer or team member for additional insights.
- [ ] Verify that the enhancement works across all relevant environments (e.g., different OS versions).
- [ ] Confirm that all dependencies are up-to-date and compatible with the changes.
- [ ] Link to the relevant Kibana PR or issue provided
- [ ] Exported detection rule(s) from Kibana to showcase the feature(s)
- [ ] Converted the exported ndjson file(s) to toml in the detection-rules repo
- [ ] Re-exported the toml rule(s) to ndjson and re-imported into Kibana
- [ ] Updated necessary unit tests to accommodate the feature
- [ ] Applied min_compat restrictions to limit the feature to a specified minimum stack version
- [ ] Executed all unit tests locally with a test toml rule to confirm passing
- [ ] Included Kibana PR implementer as an optional reviewer for insights on the feature
- [ ] Implemented requisite downgrade functionality
- [ ] Cross-referenced the feature with product documentation for consistency
- [ ] Incorporated a comprehensive test rule in unit tests for full schema coverage
- [ ] Conducted system testing, including fleet, import, and create APIs (e.g., run `make test-remote-cli`)
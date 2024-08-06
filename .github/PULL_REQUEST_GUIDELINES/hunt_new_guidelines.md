## Hunt: New - Guidelines

Welcome to the `hunting` folder within the `detection-rules` repository! This directory houses a curated collection of threat hunting queries designed to enhance security monitoring and threat detection capabilities using the Elastic Stack.

### Documentation and Context

- [ ] Detailed description of the Hunt.
- [ ] List any new fields required in ECS/data sources.
- [ ] Link related issues or PRs.
- [ ] Include references.
- [ ] Field Usage: Ensure standardized fields for compatibility across different data environments and sources.

### Hunt Metadata Checks

- [ ] `author`: The name of the individual or organization authoring the rule.
- [ ] `creation_date` matches the date of creation PR initially merged.
- [ ] `min_stack_version` supports the widest stack versions.
- [ ] `name` and `description` are descriptive and typo-free.
- [ ] `language`: The query language(s) used in the rule, such as `KQL`, `EQL`, `ES|QL`, `OsQuery`, or `YARA`.
- [ ] `query` is inclusive, not overly exclusive, considering performance for diverse environments.
- [ ] `integration` aligns with the `index`. Ensure updates if the integration is newly introduced.
- [ ] `setup` includes necessary steps to configure the integration.
- [ ] `note` includes additional information (e.g., Triage and analysis investigation guides, timeline templates).
- [ ] `tags` are relevant to the threat and align with `EXPECTED_HUNT_TAGS` in `definitions.py`.
- [ ] `threat`, `techniques`, and `subtechniques` map to ATT&CK whenever possible.

### Testing and Validation

- [ ] Evidence of testing and detecting the expected threat.
- [ ] Check for the existence of coverage to prevent duplication.
- [ ] Generate Markdown: Run `python generate_markdown.py` to update the documentation.

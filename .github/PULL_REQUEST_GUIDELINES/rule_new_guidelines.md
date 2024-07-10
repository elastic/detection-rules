## Rule: New - Guidelines

These guidelines serve as a reminder set of considerations when proposing a new rule.

### Documentation and Context

- [ ] Detailed description of the rule.
- [ ] List any new fields required in ECS/data sources.
- [ ] Link related issues or PRs.
- [ ] Include references.

### Rule Metadata Checks

- [ ] `creation_date` matches the date of creation PR initially merged.
- [ ] `min_stack_version` should support the widest stack versions.
- [ ] `name` and `description` should be descriptive and not include typos.
- [ ] `query` should be inclusive, not overly exclusive.
- [ ] `min_stack_comments` and `min_stack_version` should be included if the rule is only compatible starting from a specific stack version.
- [ ] `integration` should align with the `index`. If the integration is newly introduced, ensure the manifest and schemas are updated.
- [ ] `setup` should include the necessary steps to configure the integration.
- [ ] `note` should include any additional information (e.g. Triage and analysis investigation guides, timeline templates).
- [ ] `tags` should be relevant to the threat and align/added to the `EXPECTED_RULE_TAGS` in the definitions.py file.

### Testing and Validation

- [ ] Provide evidence of testing and detecting the expected threat.
- [ ] Check for existence of coverage to prevent duplication.

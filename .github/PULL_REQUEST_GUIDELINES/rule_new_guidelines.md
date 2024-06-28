## Rule: New - Guidelines

These guidelines serve as a reminder set of considerations when proposing a new rule.

### Documentation and Context

- [ ] Detailed description of the rule.
- [ ] List any new fields required in ECS/data sources.
- [ ] Link related issues or PRs.
- [ ] Include references.

### Rule Metadata Checks

- [ ] `creation_date` matches the date of creation PR initially merged.
- [ ] `min_endpoint_version` should support the widest stack versions.
- [ ] `name` and `description` should be descriptive and not include typos.
- [ ] `query` should be inclusive, not overly exclusive.
- [ ] `message_template` should include indices based on sequence.
- [ ] `rule.response` field values should be valid and align with the response action (e.g., low FP for kill process).

### Testing and Validation

- [ ] Provide evidence of testing and detecting the expected threat.
- [ ] Check for existence of coverage to prevent duplication.

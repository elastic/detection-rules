## Rule: Promote - Guidelines

These guidelines serve as a reminder set of considerations when recommending a rule for promotion to production.

### Documentation and Context

- [ ] Provide a link to the rule.
- [ ] Detailed description of the promotion justification.
- [ ] Include analysis of the rule's efficacy in diagnostic mode.
- [ ] Provide example data or screenshots.
- [ ] Provide telemetry query to validate promotion justification.

### Rule Metadata Checks

- [ ] `Release - production` minimum incubation period 14 days.
- [ ] `min_endpoint_version` should support the widest stack versions.
- [ ] `name` should not include typos.
- [ ] `description` should be descriptive and not include typos.
- [ ] `query` should be inclusive, not overly exclusive.
- [ ] `message_template` should include indices based on sequence.
- [ ] `rule.response` field values should be valid and align with the response action (e.g., low FP for kill process).

### Testing and Validation

- [ ] Ensure that the rule's performance is satisfactory and does not negatively impact the stack.
- [ ] Validate that the rule has a low false positive rate.
- [ ] Ensure that the rule has been thoroughly reviewed and tested in different telemetry environments.

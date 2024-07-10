## Rule: Tuning - Guidelines

These guidelines serve as a reminder set of considerations when tuning an existing rule.

### Documentation and Context

- [ ] Detailed description of the suggested changes.
- [ ] Provide example JSON data or screenshots.
- [ ] Provide evidence of FP (False Positive) reduction.
- [ ] Ensure the tuning includes necessary updates to the release documentation and versioning.

### Rule Metadata Checks

- [ ] `updated_date` matches the date of tuning PR merged.
- [ ] `min_stack_version` should support the widest stack versions.
- [ ] `name` and `description` should be descriptive and not include typos.
- [ ] `query` should be inclusive, not overly exclusive.

### Testing and Validation

- [ ] Validate that the tuned rule's performance is satisfactory and does not negatively impact the stack.
- [ ] Ensure that the tuned rule has a low false positive rate.

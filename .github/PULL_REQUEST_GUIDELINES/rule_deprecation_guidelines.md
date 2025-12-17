## Rule: Deprecation - Guidelines

These guidelines serve as a reminder set of considerations when recommending the deprecation of a rule.

### Documentation and Context

- [ ] Description of the reason for deprecation.
- [ ] Include any context or historical data supporting the deprecation decision.

### Rule Metadata Checks

- [ ] `deprecated = true` added to the rule metadata.
- [ ] `updated_date` should be the date of the PR.

### Testing and Validation

- [ ] A prior rule tuning occurred for the rule where `Deprecated - ` is prepended to the rule name, and the rule has already been released.
- [ ] Rule has be moved to the `_deprecated` directory.
- [ ] Double check gaps potentially or inadvertently introduced.
- [ ] Provide evidence that the rule is no longer needed or has been replaced (e.g., alternative rules, updated detection methods).

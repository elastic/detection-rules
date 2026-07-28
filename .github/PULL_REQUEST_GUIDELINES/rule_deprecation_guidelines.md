## Rule: Deprecation - Guidelines

These guidelines serve as a reminder set of considerations when recommending the deprecation of a rule.

### Documentation and Context

- [ ] Description of the reason for deprecation.
- [ ] Include any context or historical data supporting the deprecation decision.

### Rule Metadata Checks

- [ ] `maturity = "deprecated"` added to the rule metadata.
- [ ] `deprecation_date` set to the date of the PR and `updated_date` matches.
- [ ] `deprecated_reason` added to `[metadata]` with a short explanation (e.g. `"Replaced by <rule name>"`). Required in the same PR that flips `maturity = "deprecated"`; surfaced in Kibana on stacks >= 9.4.

### Testing and Validation

- [ ] A prior rule tuning occurred for the rule where `Deprecated - ` is prepended to the rule name, and the rule has already been released.
- [ ] Rule has be moved to the `_deprecated` directory.
- [ ] Double check gaps potentially or inadvertently introduced.
- [ ] Provide evidence that the rule is no longer needed or has been replaced (e.g., alternative rules, updated detection methods).

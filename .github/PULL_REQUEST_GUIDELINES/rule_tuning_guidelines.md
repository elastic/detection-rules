## Rule: Tuning - Guidelines

These guidelines serve as a reminder set of considerations when tuning an existing rule.

### Documentation and Context

- [ ] Detailed description of the suggested changes.
- [ ] Provide example JSON data or screenshots.
- [ ] Provide evidence of reducing benign events mistakenly identified as threats (False Positives).
- [ ] Provide evidence of enhancing detection of true threats that were previously missed (False Negatives).
- [ ] Provide evidence of optimizing resource consumption and execution time of detection rules (Performance).
- [ ] Provide evidence of specific environment factors influencing customized rule tuning (Contextual Tuning).
- [ ] Provide evidence of improvements made by modifying sensitivity by changing alert triggering thresholds (Threshold Adjustments).
- [ ] Provide evidence of refining rules to better detect deviations from typical behavior (Behavioral Tuning).
- [ ] Provide evidence of improvements of adjusting rules based on time-based patterns (Temporal Tuning).
- [ ] Provide reasoning of adjusting priority or severity levels of alerts (Severity Tuning).
- [ ] Provide evidence of improving quality integrity of our data used by detection rules (Data Quality).
- [ ] Ensure the tuning includes necessary updates to the release documentation and versioning.

### Rule Metadata Checks

- [ ] `updated_date` matches the date of tuning PR merged.
- [ ] `min_stack_version` should support the widest stack versions.
- [ ] `name` and `description` should be descriptive and not include typos.
- [ ] `query` should be inclusive, not overly exclusive. Review to ensure the original intent of the rule is maintained.

### Testing and Validation

- [ ] Validate that the tuned rule's performance is satisfactory and does not negatively impact the stack.
- [ ] Ensure that the tuned rule has a low false positive rate.

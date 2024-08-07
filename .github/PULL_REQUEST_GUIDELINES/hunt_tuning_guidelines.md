## Hunt: Tuning - Guidelines

These guidelines serve as a reminder set of considerations when tuning an existing Hunt.

### Documentation and Context

- [ ] Detailed description of the suggested changes.
- [ ] Provide example JSON data or screenshots.
- [ ] Evidence of reducing benign events mistakenly identified as threats (False Positives).
- [ ] Evidence of enhancing detection of true threats that were previously missed (False Negatives).
- [ ] Evidence of optimizing resource consumption and execution time of detection rules (Performance).
- [ ] Evidence of specific environment factors influencing customized hunt tuning (Contextual Tuning).
- [ ] Evidence of improvements by modifying sensitivity (Threshold Adjustments).
- [ ] Evidence of refining hunts to better detect deviations from typical behavior (Behavioral Tuning).
- [ ] Evidence of improvements based on time-based patterns (Temporal Tuning).
- [ ] Reasoning for adjusting priority or severity levels of alerts (Severity Tuning).
- [ ] Evidence of improving the quality integrity of data used by hunts (Data Quality).
- [ ] Ensure necessary updates to release documentation and versioning.
- [ ] Field Usage: Ensure standardized fields for compatibility across different data environments and sources.

### Hunt Metadata Checks

- [ ] `author`: The name of the individual or organization authoring the rule.
- [ ] `updated_date` matches the date of tuning PR merged.
- [ ] `min_stack_version` supports the widest stack versions.
- [ ] `name` and `description` are descriptive and typo-free.
- [ ] `language`: The query language(s) used in the rule, such as `KQL`, `EQL`, `ES|QL`, `OsQuery`, or `YARA`.
- [ ] `query` is inclusive, not overly exclusive. Review to ensure the original intent of the hunt is maintained.
- [ ] `integration` aligns with the `index`. Ensure updates if the integration is newly introduced.
- [ ] `setup` includes necessary steps to configure the integration.
- [ ] `note` includes additional information (e.g., Triage and analysis investigation guides, timeline templates).
- [ ] `tags` are relevant to the threat and align with `EXPECTED_HUNT_TAGS` in `definitions.py`.
- [ ] `threat`, `techniques`, and `subtechniques` map to ATT&CK whenever possible.

### Testing and Validation

- [ ] Generate Markdown: Run `python generate_markdown.py` to update the documentation.
- [ ] Validate the tuned hunt's performance and ensure it does not negatively impact the stack.
- [ ] Ensure the tuned hunt has a low false positive rate.
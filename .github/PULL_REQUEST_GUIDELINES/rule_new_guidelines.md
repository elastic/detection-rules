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
- [ ] `query` should be inclusive, not overly exclusive, considering performance for diverse environments. Non ecs fields should be added to `non-ecs-schema.json` if not available in an integration.
- [ ] `min_stack_comments` and `min_stack_version` should be included if the rule is only compatible starting from a specific stack version.
- [ ] `index` pattern should be neither too specific nor too vague, ensuring it accurately matches the relevant data stream (e.g., use logs-endpoint.process-* for process data).
- [ ] `integration` should align with the `index`. If the integration is newly introduced, ensure the manifest, schemas, and `new_rule.yaml` template are updated.
- [ ] `setup` should include the necessary steps to configure the integration.
- [ ] `note` should include any additional information (e.g. Triage and analysis investigation guides, timeline templates).
- [ ] `tags` should be relevant to the threat and align/added to the `EXPECTED_RULE_TAGS` in the definitions.py file.
- [ ] `threat`, `techniques`, and `subtechniques` should map to ATT&CK always if possible.

#### New BBR Rules
- [ ] `building_block_type` should be included if the rule is a building block and the rule should be located in the `rules_building_block` folder.
- [ ] `bypass_bbr_timing` should be included if adding custom lookback timing to the rule.

### Testing and Validation

- [ ] Provide evidence of testing and detecting the expected threat.
- [ ] Check for existence of coverage to prevent duplication.

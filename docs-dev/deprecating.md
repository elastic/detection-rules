# Deprecating rules

Rules that have been version locked (added to [version.lock.json](../detection_rules/etc/version.lock.json)), which also means they
have been added to the detection engine in Kibana, must be properly [deprecated](#steps-to-properly-deprecate-a-rule).

If a rule was never version locked (not yet pushed to Kibana or still in non-`production` `maturity`), the rule can
simply be removed with no additional changes, or updated the `maturity = "development"`, which will leave it out of the
release package to Kibana.


## Steps to properly deprecate a rule

1. Update the `maturity` to `deprecated`
2. Move the rule file to [rules/_deprecated](../rules/_deprecated)
3. Add `deprecation_date` and update `updated_date` to match
4. Add `deprecated_reason` in `[metadata]` with a short explanation (e.g. "Replaced by <rule name>"). Required in the
   same PR that flips `maturity = "deprecated"`; surfaced in Kibana on stacks >= 9.4 and ignored on older stacks.

Next time the versions are locked, the rule will be added to the [deprecated_rules.json](../detection_rules/etc/deprecated_rules.json)
file, and `deprecated_reason` is copied into the package asset (gated at build time by `MIN_STACK_VERSION_DEPRECATED_STUBS`).


### Using the deprecate-rule command

Alternatively, you can run `python -m detection_rules dev deprecate-rule <rule-file>`, which will perform all the steps

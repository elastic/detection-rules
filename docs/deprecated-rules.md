# Deprecated prebuilt detection rules

Elastic periodically retires prebuilt detection rules that have been superseded by improved coverage, renamed, or are no longer relevant to current threat landscapes. Deprecated rules are moved to a separate category rather than deleted so that users who have customized or enabled them retain a reference.

## What happens to deprecated rules

Deprecated rules continue to function normally if you have enabled them. Elastic no longer maintains them, which means:

- They do not receive threat intelligence updates or query improvements.
- They may not reflect current data source field names or index patterns.
- They are not tested against new Elastic Stack releases.

## Recommended actions

When a rule is deprecated, Elastic typically provides a replacement rule with improved detection logic. To transition:

1. Identify the replacement rule using the rule name or description references in the deprecated rule's documentation.
2. Enable the replacement rule and tune it to your environment.
3. Once satisfied with the replacement, you can disable or delete the deprecated rule.

If no replacement is listed, the threat the rule addressed may no longer be relevant, or coverage may have been incorporated into a broader rule.

## Managing deprecated rules in Kibana

To view and manage deprecated rules in Kibana, go to **Security → Rules → Detection Rules** and filter by the **Deprecated** tag. See [manage detection rules](docs-content://solutions/security/detect-and-alert/manage-detection-rules.md) for full instructions.

# Password Spraying from Repeat Source

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies password spraying attacks in Okta where the same source IP attempts to authenticate to multiple accounts with invalid credentials. Adversaries may attempt to use a single source IP to avoid detection and bypass account lockout policies.

- **UUID:** `1c2d2b08-71ee-11ef-952e-f661ea17fbcc`
- **Integration:** [okta](https://docs.elastic.co/integrations/okta)
- **Language:** `[ES|QL]`
- **Source File:** [Password Spraying from Repeat Source](../queries/initial_access_password_spraying_from_repeat_source.toml)

## Query

```sql
from logs-okta*
| where @timestamp > NOW() - 7 day

// truncate the timestamp to daily intervals
| eval target_time_window = DATE_TRUNC(1 days, @timestamp)
| where

// filter for invalid credential events
    event.action == "user.session.start"
    and okta.outcome.result == "FAILURE"
    and okta.outcome.reason == "INVALID_CREDENTIALS"
| stats
    // count the distinct number of targeted accounts
    target_count = count_distinct(okta.actor.alternate_id),

    // count the number of invalid credential events for each source IP
    source_count = count(*) by target_time_window, okta.client.ip

// filter for source IPs with more than 5 invalid credential events
| where target_count >= 10
```

## Notes

- `okta.actor.alternate_id` are the targeted accounts.
- Pivot for successful logins from the same source IP by searching for `event.action` equal to `user.session.start` or `user.authentication.verify` where the outcome is `SUCCESS`.
- User agents can be used to identify anomalous behavior, such as a user agent that is not associated with a known application or user.
- The `target_count` can be adjusted depending on the organization's account lockout policy or baselined behavior.

## MITRE ATT&CK Techniques

- [T1078.004](https://attack.mitre.org/techniques/T1078/004)

## License

- `Elastic License v2`

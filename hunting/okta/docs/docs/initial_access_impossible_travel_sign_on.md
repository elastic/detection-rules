# Multi-Factor Authentication (MFA) Push Notification Bombing

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies when a user denies multiple push notifications for multi-factor authentication (MFA) in rapid succession. Adversaries may attempt to deny push notifications to flood the target user's device with notifications, causing the user to ignore legitimate notifications or potentially disable MFA. This query identifies when a user denies more than 5 push notifications in a single hour.

- **UUID:** `7c51fe3e-6ae9-11ef-919d-f661ea17fbcc`
- **Integration:** [okta](https://docs.elastic.co/integrations/okta)
- **Language:** `[ES|QL]`
- **Source File:** [Multi-Factor Authentication (MFA) Push Notification Bombing](../queries/initial_access_impossible_travel_sign_on.toml)

## Query

```sql
from logs-okta.system*
| where @timestamp > NOW() - 7 day
| where event.dataset == "okta.system"

    // filter on successful sign-on events only
    and okta.event_type == "policy.evaluate_sign_on"
    and okta.outcome.result in ("ALLOW", "SUCCESS")

// Truncate the timestamp to 15 minute intervals
| eval time_window = DATE_TRUNC(15 minutes, @timestamp)

// Count the number of successful sign-on events for each user every 15 minutes
| stats country_count = count_distinct(client.geo.country_name) by okta.actor.alternate_id, time_window

// Filter for users who sign on from more than one country in a 15 minute interval
| where country_count < 2
```

## Notes

- `okta.actor.alternate_id` would be target of the threat adversary
- Pivoting into a potential compromise requires an additional search for `okta.outcome.result` being `SUCCESS` for any `user.authentication*` value for `okta.event_type`
- For a smaller window (rapid denies), reduce from 1 hour to 30 minutes or lower

## MITRE ATT&CK Techniques

- [T1556.006](https://attack.mitre.org/techniques/T1556/006)

## License

- `Elastic License v2`

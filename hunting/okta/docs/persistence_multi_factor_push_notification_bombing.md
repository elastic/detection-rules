# Multi-Factor Authentication (MFA) Push Notification Bombing

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies when a user denies multiple push notifications for multi-factor authentication (MFA) in rapid succession. Adversaries may attempt to deny push notifications to flood the target user's device with notifications, causing the user to ignore legitimate notifications or potentially disable MFA. This query identifies when a user denies more than 5 push notifications in a single hour.

- **UUID:** `7c51fe3e-6ae9-11ef-919d-f661ea17fbcc`
- **Integration:** [okta](https://docs.elastic.co/integrations/okta)
- **Language:** `[ES|QL]`
- **Source File:** [Multi-Factor Authentication (MFA) Push Notification Bombing](../queries/persistence_multi_factor_push_notification_bombing.toml)

## Query

```sql
from logs-okta.system*
| where @timestamp > NOW() - 7 day

// Filter for deny push notifications for multi-factor authentication
| where event.dataset == "okta.system" and event.action == "user.mfa.okta_verify.deny_push"

// Truncate the timestamp to hourly intervals
| eval hourly_count = date_trunc(1 hour, event.ingested)

// Count the number of deny push notifications for each user every hour
| stats hourly_denies = count(*) by okta.actor.alternate_id, hourly_count

// Filter for users who deny more than 5 push notifications in a single hour
| where hourly_denies > 5
```

## Notes

- `okta.actor.alternate_id` would be target of the threat adversary
- Pivoting into a potential compromise requires an additional search for `okta.outcome.result` being `SUCCESS` for any `user.authentication*` value for `okta.event_type`
- For a smaller window (rapid denies), reduce from 1 hour to 30 minutes or lower

## MITRE ATT&CK Techniques

- [T1556.006](https://attack.mitre.org/techniques/T1556/006)

## License

- `Elastic License v2`

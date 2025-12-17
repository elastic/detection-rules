# Rapid MFA Deny Push Notifications (MFA Bombing)

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies MFA bombing attacks in Okta. Adversaries may attempt to flood a user with multiple MFA push notifications to disrupt operations or gain unauthorized access to accounts. This query identifies when a user has more than 5 MFA deny push notifications in a 10 minute window.

- **UUID:** `223451b0-6eca-11ef-a070-f661ea17fbcc`
- **Integration:** [okta](https://docs.elastic.co/integrations/okta)
- **Language:** `[ES|QL]`
- **Source File:** [Rapid MFA Deny Push Notifications (MFA Bombing)](../queries/credential_access_mfa_bombing_push_notications.toml)

## Query

```sql
from logs-okta*
| where @timestamp > NOW() - 7 day

// Truncate the timestamp to 10 minute windows
| eval target_time_window = DATE_TRUNC(10 minutes, @timestamp)

// Filter for MFA deny push notifications
| where event.action == "user.mfa.okta_verify.deny_push"

// Count the number of MFA deny push notifications for each user in each 10 minute window
| stats deny_push_count = count(*) by target_time_window, okta.actor.alternate_id

// Filter for users with more than 5 MFA deny push notifications
| where deny_push_count >= 5
```

## Notes

- `okta.actor.alternate_id` is the targeted user account.
- Pivot and search for `event.action` is `user.authentication.auth_via_mfa` to determine if the target user accepted the MFA push notification.
- If a MFA bombing attack is suspected, both username and password are required prior to MFA push notifications. Thus the credentials are likely compromised.

## MITRE ATT&CK Techniques

- [T1621](https://attack.mitre.org/techniques/T1621)

## License

- `Elastic License v2`

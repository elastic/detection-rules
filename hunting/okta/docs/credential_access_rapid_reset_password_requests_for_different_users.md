# Rapid Reset Password Requests for Different Users

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies rapid reset password requests for different users in Okta. Adversaries may attempt to reset passwords for multiple users in rapid succession to gain unauthorized access to accounts or disrupt operations. This query identifies when the source user is different from the target user in reset password events and filters for users with more than 15 reset password attempts.

- **UUID:** `c784106e-6ae8-11ef-919d-f661ea17fbcc`
- **Integration:** [okta](https://docs.elastic.co/integrations/okta)
- **Language:** `[ES|QL]`
- **Source File:** [Rapid Reset Password Requests for Different Users](../queries/credential_access_rapid_reset_password_requests_for_different_users.toml)

## Query

```sql
from logs-okta.system*
| where @timestamp > NOW() - 7 day

// Filter for reset password events where the source user is different from the target user
| where event.dataset == "okta.system" and event.action == "user.account.reset_password" and source.user.full_name != user.target.full_name

// Extract relevant fields
| keep @timestamp, okta.actor.alternate_id, okta.debug_context.debug_data.dt_hash, user.target.full_name, okta.outcome.result

// Count the number of reset password attempts for each user
| stats
    user_count = count_distinct(user.target.full_name),
    reset_counts = by okta.actor.alternate_id, source.user.full_name, okta.debug_context.debug_data.dt_hash

// Filter for more than 10 unique users and more than 15 reset password attempts by the source
| where user_count > 10 and reset_counts > 15
```

## Notes

- `okta.actor.alternate_id` is the potentially compromised account
- An API access token may have been compromised, where okta.actor.alternate_id reflects the owner
- To identify a list of tokens this user created, search for the `okta.actor.alternate_id` where `event.action` is `system.api_token*` which may require a larger time window

## MITRE ATT&CK Techniques

- [T1098.001](https://attack.mitre.org/techniques/T1098/001)

## License

- `Elastic License v2`

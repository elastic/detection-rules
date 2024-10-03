# Rare Occurrence of Domain with User Authentication Events

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies rare occurrences of user authentication events for an Okta user whose registered user account email address has a domain that is not commonly seen in the organization. Adversaries may use compromised credentials or tokens to create a new user account with a domain that is not commonly seen in the organization because they do not have access to a valid email address within that domain.

- **UUID:** `f3bc68f4-71e9-11ef-952e-f661ea17fbcc`
- **Integration:** [okta](https://docs.elastic.co/integrations/okta)
- **Language:** `[ES|QL]`
- **Source File:** [Rare Occurrence of Domain with User Authentication Events](../queries/persistence_rare_domain_with_user_authentication.toml)

## Query

```sql
from logs-okta*
| where @timestamp > NOW() - 7 day
| where
    // Filter for user authentication events
    okta.actor.alternate_id is not null
    and event.action LIKE "user.authentication*"

// Extract the top-level domain (TLD) from the user's email address
| dissect okta.actor.alternate_id "%{}@%{tld}"

// Count the number of user authentication events for each TLD
| stats tld_auth_counts = count(*) by tld

// Filter for TLDs with less than or equal to 5 user authentication events
| where tld_auth_counts <= 5

// Sort the results by the number of user authentication events in ascending order
| sort tld_auth_counts asc
```

## Notes

- Pivot into potential compromised accounts by searching for the `okta.actor.alternate_id` in `okta.target` where `event.action` is `user.lifecycle.create`. This would identify when the user account was created. The `okta.actor.alternate_id` of this event will also be the potential compromised account.

## MITRE ATT&CK Techniques

- [T1078.004](https://attack.mitre.org/techniques/T1078/004)

## License

- `Elastic License v2`

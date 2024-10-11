# Successful Impossible Travel Sign-On Events

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies when a user successfully signs on from more than one country in a 15 minute interval. Adversaries may compromise authentication credentials for users or clients and attempt to authenticate from a separate country that the user has not previously authenticated from.

- **UUID:** `31585786-71f4-11ef-9e99-f661ea17fbcc`
- **Integration:** [okta](https://docs.elastic.co/integrations/okta)
- **Language:** `[ES|QL]`
- **Source File:** [Successful Impossible Travel Sign-On Events](../queries/initial_access_impossible_travel_sign_on.toml)

## Query

```sql
from logs-okta.system*
| where @timestamp > NOW() - 7 day
| where event.dataset == "okta.system"

    // filter on successful sign-on events only
    and okta.event_type == "policy.evaluate_sign_on"
    and okta.outcome.result in ("ALLOW", "SUCCESS")

// Truncate the timestamp to 1 hour intervals
| eval time_window = DATE_TRUNC(1 hours, @timestamp)

// Count the number of successful sign-on events for each user every 15 minutes
| stats country_count = count_distinct(client.geo.country_name) by okta.actor.alternate_id, time_window

// Filter for users who sign on from more than one country in a 15 minute interval
| where country_count >= 2
```

## Notes

- `okta.actor.alternate_id` would be target of the threat adversary
- Pivoting into a potential compromise requires an additional search for `okta.outcome.result` being `SUCCESS` for any `user.authentication*` value for `okta.event_type`
- Pivot to any additional Okta logs after authentication to determine if activity is still being reported by separate countries.

## MITRE ATT&CK Techniques

- [T1078.004](https://attack.mitre.org/techniques/T1078/004)

## License

- `Elastic License v2`

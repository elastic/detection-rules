# Identify High Average of Failed Daily Authentication Attempts

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies when the average number of failed daily authentication attempts is higher than normal in Okta. Adversaries may attempt to brute force user credentials to gain unauthorized access to accounts. This query calculates the average number of daily failed authentication attempts for each user and identifies when the average is higher than normal.

- **UUID:** `c8a35a26-71f1-11ef-9c4e-f661ea17fbcc`
- **Integration:** [okta](https://docs.elastic.co/integrations/okta)
- **Language:** `[ES|QL]`
- **Source File:** [Identify High Average of Failed Daily Authentication Attempts](../queries/initial_access_higher_than_average_failed_authentication.toml)

## Query

```sql
from logs-okta*
| where @timestamp > NOW() - 7 day

// truncate the timestamp to daily intervals
| eval target_time_window = DATE_TRUNC(1 days, @timestamp)
| where

    // filter for invalid credential authentication events
    event.action == "user.session.start"
    and okta.outcome.result == "FAILURE"
    and okta.outcome.reason == "INVALID_CREDENTIALS"
    and okta.actor.type == "User"

| stats
    // count the number of daily failed logins for each day and user
    failed_daily_logins = count(*) by target_time_window, okta.actor.alternate_id

| stats
    // calculate the average number of daily failed logins for each day
    avg_daily_logins = avg(failed_daily_logins) by target_time_window

// sort the results by the average number of daily failed logins in descending order
| sort avg_daily_logins desc
```

## Notes

- Pivot to users by only keeping the first stats statement where `okta.actor.alternate_id` is the targeted accounts.
- Pivot for successful logins from the same source IP by searching for `event.action` equal to `user.session.start` or `user.authentication.verify` where the outcome is `SUCCESS`.
- User agents can be used to identify anomalous behavior, such as a user agent that is not associated with a known application or user.
- Another `WHERE` count can be added to the query if activity has been baseline to filter out known behavior.

## MITRE ATT&CK Techniques

- [T1078.004](https://attack.mitre.org/techniques/T1078/004)

## License

- `Elastic License v2`

# Multiple Application SSO Authentication from the Same Source

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies when a user authenticates to multiple applications using Single Sign-On (SSO) from the same source. Adversaries may attempt to authenticate to multiple applications using SSO to gain unauthorised access to sensitive data or resources. Adversaries also rely on refresh tokens to maintain access to applications and services. This query identifies when a source IP authenticates to more than 15 applications using SSO within a 5-minute window.

- **UUID:** `03bce3b0-6ded-11ef-9282-f661ea17fbcc`
- **Integration:** [okta](https://docs.elastic.co/integrations/okta)
- **Language:** `[ES|QL]`
- **Source File:** [Multiple Application SSO Authentication from the Same Source](../queries/defense_evasion_multiple_application_sso_authentication_repeat_source.toml)

## Query

```sql
from logs-okta*
| eval target_time_window = DATE_TRUNC(5 minutes, @timestamp)

// truncate the timestamp to a 5-minute window
| where @timestamp > now() - 7 day

// filter for SSO authentication events where the authentication step is 0
// filter on request URI string '/app/' to identify applications for a user
| where
    event.action == "user.authentication.sso"
    and okta.authentication_context.authentication_step == 0
    and okta.debug_context.debug_data.request_uri RLIKE "(.*)/app/(.*)"

// dissect the request URI to extract the target application
| dissect okta.debug_context.debug_data.request_uri"%{?}/app/%{target_application}/"

// count the number of unique applications per source IP and user in a 5-minute window
| stats application_count = count_distinct(target_application), window_count = count(*) by target_time_window, source.ip, okta.actor.alternate_id

// filter for at least 15 distinct applications authenticated from a single source IP
| where application_count > 15
```

## Notes

- `okta.debug_context.debug_data.dt_hash` field can be used to identify the device token hash used for authentication. This can be used to pivot for additional activity from the same device.
- `okta.debug_context.debug_data.flattened` contains additional information such as request ID, trace ID, sign-on mode and more to review for anomalies in the authentication flow.
- `okta.request.ip_chain` can be used to understand more about the source address, which is potentially useful for profiling.
- If `okta.security_context.is_proxy` is `true`, then an adversary may be attempting to mask their true source behind a proxy or VPN.

## MITRE ATT&CK Techniques

- [T1550.001](https://attack.mitre.org/techniques/T1550/001)

## License

- `Elastic License v2`

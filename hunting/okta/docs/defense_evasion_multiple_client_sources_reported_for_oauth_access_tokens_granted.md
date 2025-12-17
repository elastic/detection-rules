# OAuth Access Token Granted for Public Client App from Multiple Client Addresses

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies when a public client app successfully retrieves an OAuth access token using client credentials from multiple client addresses. For public client applications in Okta that leverage OAuth, client credentials can be used to retrieve access tokens without user consent. Unsecured credentials may be compromised by an adversary who may use them to request an access token on behalf of the public client app.

- **UUID:** `38d82c2c-71d9-11ef-a9be-f661ea17fbcc`
- **Integration:** [okta](https://docs.elastic.co/integrations/okta)
- **Language:** `[ES|QL]`
- **Source File:** [OAuth Access Token Granted for Public Client App from Multiple Client Addresses](../queries/defense_evasion_multiple_client_sources_reported_for_oauth_access_tokens_granted.toml)

## Query

```sql
from logs-okta.system*
| where @timestamp > NOW() - 21 day

// truncate the timestamp to 1 day
| eval target_time_window = DATE_TRUNC(1 days, @timestamp)
| where

    // filter for successful OAuth access token grant requests
    event.action == "app.oauth2.as.token.grant.access_token"
    and event.outcome == "success"
    and event.dataset == "okta.system"

    // filter for public client apps
    and okta.actor.type == "PublicClientApp"

    // ignore Elastic Okta integration and DataDog actors
    and not (okta.actor.display_name LIKE "Okta*" or okta.actor.display_name LIKE "Datadog*")

// count the number of access tokens granted by the same public client app in a day
| stats token_granted_count = count(*), unique_client_ip = count_distinct(okta.client.ip) by target_time_window, okta.actor.display_name

// filter where access tokens were granted on the same day but client addresses are different
| where unique_client_ip >= 2 and token_granted_count >= 2
```

## Notes

- Review `okta.debug_context.debug_data.flattened.grantType` to identify if the grant type is `client_credentials`
- Ignore `okta.debug_context.debug_data.flattened.requestedScopes` values that indicate read-only access
- Review `okta.actor.display_name` to identify the public client app that attempted to retrieve the access token. This may help identify the compromised client credentials.
- Filter on the public client app and aggregate by `event.action` to determine what actions were taken by the public client app after the access token was granted.

## MITRE ATT&CK Techniques

- [T1550.001](https://attack.mitre.org/techniques/T1550/001)

## License

- `Elastic License v2`

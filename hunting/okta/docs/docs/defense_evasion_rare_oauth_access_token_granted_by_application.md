# Rare Occurrence of OAuth Access Token Granted to Public Client App

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies a rare occurrence of a public client app successfully retrieves an OAuth access token using client credentials as the grant type within the last 14 days. Public client applications in Okta that leverage OAuth, client credentials can be used to retrieve access tokens without user consent. Unsecured credentials may be compromised by an adversary whom may use them to request an access token on behalf of the public client app.

- **UUID:** `11666aa0-71d9-11ef-a9be-f661ea17fbcc`
- **Integration:** [okta](https://docs.elastic.co/integrations/okta)
- **Language:** `[ES|QL]`
- **Source File:** [Rare Occurrence of OAuth Access Token Granted to Public Client App](../queries/defense_evasion_rare_oauth_access_token_granted_by_application.toml)

## Query

```sql
from logs-okta.system*
| where @timestamp > NOW() - 14 day
| where

    // filter for successful OAuth access token grant requests
    event.action == "app.oauth2.as.token.grant.access_token"
    and event.outcome == "success"
    and event.dataset == "okta.system"

    // filter for public client apps
    and okta.actor.type == "PublicClientApp"

    // ignore Elastic Okta integration and DataDog actors
    and not okta.client.user_agent.raw_user_agent == "Okta-Integrations"
    and not (okta.actor.display_name LIKE "Okta%" or okta.actor.display_name LIKE "Datadog%")

// count the number of access tokens granted by the same public client app
| stats token_granted_count = count(*) by okta.actor.display_name

// filter where the public client app has only been granted an access token once in the last 14 days
| where token_granted_count == 1
```

## Notes

- Review `okta.debug_context.debug_data.flattened.grantType` to identify if the grant type is `client_credentials`
- Ignore `okta.debug_context.debug_data.flattened.requestedScopes` values that indicate read-only access
- Review `okta.actor.display_name` to identify the public client app that attempted to retrieve the access token. This may help identify the compromised client credentials.
- False-positives may exist if the public client app is new or has not been used in the last 14 days.

## MITRE ATT&CK Techniques

- [T1550.001](https://attack.mitre.org/techniques/T1550/001)

## License

- `Elastic License v2`

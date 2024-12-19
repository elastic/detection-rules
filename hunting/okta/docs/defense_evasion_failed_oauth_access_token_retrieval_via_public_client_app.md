# Failed OAuth Access Token Retrieval via Public Client App

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies when a public client app fails to retrieve an OAuth access token using client credentials because of an uauthorized scope. Adversaries may attempt to retrieve access tokens using client credentials to bypass user authentication and access resources. This query identifies when a public client app fails to retrieve an access token using client credentials and scopes that are not implicitly granted.

- **UUID:** `0b936024-71d9-11ef-a9be-f661ea17fbcc`
- **Integration:** [okta](https://docs.elastic.co/integrations/okta)
- **Language:** `[ES|QL]`
- **Source File:** [Failed OAuth Access Token Retrieval via Public Client App](../queries/defense_evasion_failed_oauth_access_token_retrieval_via_public_client_app.toml)

## Query

```sql
from logs-okta.system*
| where @timestamp > NOW() - 7 day
| where
    event.dataset == "okta.system"

    // filter on failed access token grant requests where source is a public client app
    and event.action == "app.oauth2.as.token.grant"
    and okta.actor.type == "PublicClientApp"
    and okta.outcome.result == "FAILURE"

    // filter out known Okta and Datadog actors
    and not (
        okta.actor.display_name LIKE "Okta%"
        or okta.actor.display_name LIKE "Datadog%"
    )

    // filter for scopes that are not implicitly granted
    and okta.outcome.reason == "no_matching_scope"

| keep @timestamp, event.action, okta.actor.type, okta.outcome.result, okta.outcome.reason, okta.actor.display_name
```

## Notes

- Review `okta.debug_context.debug_data.flattened.grantType` to identify if the grant type is `client_credentials`
- Ignore `okta.debug_context.debug_data.flattened.requestedScopes` values that indicate read-only access
- Review `okta.actor.display_name` to identify the public client app that attempted to retrieve the access token. This may help identify the compromised client credentials.
- Pivot for successful access token retrieval by the same public client app by searching `event.action` equal to `app.oauth2.as.token.grant.access_token` where the display name is the same.

## MITRE ATT&CK Techniques

- [T1550.001](https://attack.mitre.org/techniques/T1550/001)

## License

- `Elastic License v2`

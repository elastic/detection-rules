# Password Only Authentication

---

## Metadata

- **Author:** Elastic
- **Description:** Identifies Okta applications where password-only authentication is observed through `user.authentication.verify` events without corresponding MFA (`auth_via_mfa`) or SSO events within the selected time range. Helps identify applications that may allow authentication without an additional authentication factor.

- **UUID:** `df7e8b99-97c1-4632-b633-97a2615d1b65`
- **Integration:** [okta](https://docs.elastic.co/integrations/okta)
- **Language:** `[ES|QL]`
- **Source File:** [Password Only Authentication](../queries/password_only_auth_without_mfa.toml)

## Query

```sql
FROM logs-okta.system*
| WHERE @timestamp > NOW() - 7 day
| WHERE event.dataset == "okta.system"
    AND okta.outcome.result == "SUCCESS"
    AND okta.event_type IN (
        "user.authentication.verify",
        "user.authentication.auth_via_mfa",
        "user.authentication.sso"
    )

// Identify verification events where password is the only recorded method
| EVAL password_only_verify = CASE(
    okta.event_type == "user.authentication.verify"
    AND MV_CONTAINS(okta.target.detailEntry.methodTypeUsed, "PASSWORD")
    AND MV_COUNT(okta.target.detailEntry.methodTypeUsed) == 1,
    1, 0
)

// Flag MFA and SSO events for aggregation
| EVAL mfa_event = CASE(
    okta.event_type == "user.authentication.auth_via_mfa", 1, 0
)
| EVAL sso_event = CASE(
    okta.event_type == "user.authentication.sso", 1, 0
)

// Aggregate authentication events by application ID , here app id is a scalar field populated during ingestion with the Okta AppInstance ID.
| STATS
    password_only_events = SUM(password_only_verify),
    mfa_events = SUM(mfa_event),
    sso_events = SUM(sso_event)
  BY app_id

// Return applications with password-only events and no observed MFA or SSO events
| WHERE password_only_events > 0
    AND mfa_events == 0
    AND sso_events == 0
```

## Notes

- `okta.actor.alternate_id` identifies the user performing the authentication.
- `app_id` is a scalar field populated during ingestion with the Okta AppInstance ID.
- Confirm whether MFA is enrolled for the user and whether the sign-on policy allows password-only authentication for the application or group.
- Pivot on the same user for `user.authentication.auth_via_mfa` and `user.authentication.sso` events over a wider time range.
- Consider service accounts, break-glass accounts, applications intentionally excluded from MFA, and external identity providers when investigating results.
- The absence of MFA or SSO events does not prove that MFA is disabled.

## MITRE ATT&CK Techniques

- [T1078.004](https://attack.mitre.org/techniques/T1078/004)

## License

- `Elastic License v2`

# Azure Entra Unusual Client App Authentication Requests on Behalf of Principal Users

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query gathers evidence of Azure Entra sign-in attempts on-behalf-of a user with an unusual client app. During brute-forcing attempts, adversaries may use a custom or Azure-managed app ID to authenticate on-behalf-of a user. This is a rare event and may indicate an attempt to bypass conditional access policies (CAP) and multi-factor authentication (MFA) requirements. The app ID specified may not be commonly used by the user based on their historical sign-in activity.

- **UUID:** `ce47ec2c-fe13-11ef-9ee5-f661ea17fbcd`
- **Integration:** [azure](https://docs.elastic.co/integrations/azure)
- **Language:** `[ES|QL]`
- **Source File:** [Azure Entra Unusual Client App Authentication Requests on Behalf of Principal Users](../queries/entra_unusual_client_app_auth_request_on_behalf_of_user.toml)

## Query

```sql
from logs-azure.signinlogs*
| where @timestamp > now() - 14 day
| keep
    @timestamp,
    event.dataset,
    event.category,
    azure.signinlogs.properties.app_display_name,
    azure.signinlogs.properties.app_id,
    azure.signinlogs.properties.user_principal_name,
    azure.signinlogs.properties.status.error_code,
    azure.signinlogs.category,
    source.as.organization.name,
    event.outcome,
    source.ip
| WHERE
    // filter for failed sign-in logs related to invalid username or password
    event.dataset == "azure.signinlogs"
    and event.category == "authentication"
    and event.outcome != "success"
    and azure.signinlogs.properties.status.error_code in (50053, 50126, 50055, 50056, 50064, 50144)
    and source.as.organization.name != "MICROSOFT-CORP-MSN-AS-BLOCK"
// aggregate the number of failed sign-in attempts by user and app ID reported
| stats
    auth_via_app_count = count(*) by
    azure.signinlogs.properties.user_principal_name,
    azure.signinlogs.properties.app_display_name,
    azure.signinlogs.properties.app_id
// filter for users with less than or equal to 3 failed sign-in attempts per app
| where auth_via_app_count <= 3
| sort auth_via_app_count asc
```

## Notes

- Review `azure.signinlogs.properties.authentication_protocol` to verify the authentication method used. Non-interactive SFA is typically reserved for automated processes or legacy authentication methods.
- Review `azure.signinlogs.properties.error_code` to identify the specific error codes associated with the failed authentication attempts. Common error codes include `50053` for account lockouts, `50126` for invalid credentials, and `50055` for expired passwords.
- Investigate `azure.signinlogs.properties.user_principal_name` to determine whether the user typically authenticates using SFA. Unusual use by regular accounts may indicate compromise.
- Analyze `source.as.organization.name` to determine if the request originated from a known hosting provider, VPN, or anonymization service that is unexpected in your environment.
- Examine `source.address` to check if the IP address is associated with previous suspicious activity, high-risk geolocations, or known threat infrastructure.
- Pivot on `azure.signinlogs.properties.user_principal_name` to identify any other high-risk activities within the same session.
- Correlate findings with `azure.signinlogs.properties.authentication_processing_details` to identify possible legacy protocol usage, token replay, permission scopes or bypass mechanisms.

## MITRE ATT&CK Techniques

- [T1078.004](https://attack.mitre.org/techniques/T1078/004)
- [T1110.003](https://attack.mitre.org/techniques/T1110/003)

## References

- https://securityscorecard.com/wp-content/uploads/2025/02/MassiveBotnet-Report_022125_03.pdf

## License

- `Elastic License v2`

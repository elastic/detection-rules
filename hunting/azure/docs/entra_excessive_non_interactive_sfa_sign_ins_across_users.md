# Azure Entra Excessive Single-Factor Non-Interactive Sign-Ins

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query gathers evidence of password spraying attempts against Azure Entra ID user accounts by detecting a high number of failed non-interactive single-factor authentication (SFA) login attempts within a 10-minute window. Attackers may attempt to brute force user accounts to gain unauthorized access to Azure Entra ID services or validate compromised credentials. Non-interactive SFA login attempts bypass conditional-access policies (CAP) and multi-factor authentication (MFA) requirements, making them a high-risk vector for unauthorized access. Adversaries may attempt this to identify which accounts are still valid from acquired credentials via phishing, infostealers, or other means.

- **UUID:** `a9281116-fde0-11ef-9ee5-f661ea17fbcd`
- **Integration:** [azure](https://docs.elastic.co/integrations/azure)
- **Language:** `[ES|QL]`
- **Source File:** [Azure Entra Excessive Single-Factor Non-Interactive Sign-Ins](../queries/entra_excessive_non_interactive_sfa_sign_ins_across_users.toml)

## Query

```sql
from logs-azure.signinlogs*
| where @timestamp > now() - 14 day
| keep
    @timestamp,
    event.dataset,
    event.category,
    azure.signinlogs.properties.is_interactive,
    azure.signinlogs.properties.authentication_requirement,
    azure.signinlogs.properties.resource_display_name,
    azure.signinlogs.properties.status.error_code,
    source.as.organization.name,
    azure.signinlogs.category,
    event.outcome,
    azure.signinlogs.properties.user_principal_name,
    source.ip
// truncate the timestamp to a 10-minute window
| eval target_time_window = DATE_TRUNC(10 minutes, @timestamp)
| WHERE
  event.dataset == "azure.signinlogs"
  and event.category == "authentication"
  and azure.signinlogs.properties.is_interactive == false
  and azure.signinlogs.properties.authentication_requirement == "singleFactorAuthentication"
  and source.as.organization.name != "MICROSOFT-CORP-MSN-AS-BLOCK"
  and event.outcome != "success"
  and azure.signinlogs.properties.status.error_code in (50053, 50126, 50055, 50056, 50064, 50144)
// count the number of unique user login attempts
| stats
    unique_user_login_count = count_distinct(azure.signinlogs.properties.user_principal_name) by target_time_window, azure.signinlogs.properties.status.error_code
// filter for >= 30 failed SFA auth attempts with the same error codes
| where unique_user_login_count >= 30
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

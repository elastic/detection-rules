# Microsoft Entra ID Uncommon IP Adding Credentials to Service Principal

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query gathers evidence of a compromised Microsoft Entra ID identity creating new credentials for a service principal. This may indicate that an attacker has hijacked an Application Administrative entity and is attempting to use it escalate privileges by adding backdoor credentials to a service principal. Service principals are often used to manage permissions and access to resources in Azure, making them a valuable target for attackers. 
- **UUID:** `d2dd0288-0a8c-11f0-b738-f661ea17fbcc`
- **Integration:** [azure](https://docs.elastic.co/integrations/azure)
- **Language:** `[ES|QL]`
- **Source File:** [Microsoft Entra ID Uncommon IP Adding Credentials to Service Principal](../queries/entra_service_principal_credentials_added_to_rare_app.toml)

## Query

```sql
FROM logs-azure.auditlogs*
| WHERE @timestamp > now() - 60 day
| WHERE
    event.dataset == "azure.auditlogs"
    AND azure.auditlogs.operation_name == "Add service principal credentials"
    AND event.outcome == "success"
| EVAL
    // Extract appId from additional_details
    azure.auditlogs.properties.additional_details.appId = MV_SLICE(azure.auditlogs.properties.additional_details.value, 0)::STRING
| WHERE
    // Ensure appId is UUIDv4 format
    azure.auditlogs.properties.additional_details.appId RLIKE """[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"""
    // Use the below filter to limit results to credential additions associated with known service principals (e.g. Commvault)
    // AND (azure.auditlogs.properties.target_resources.`0`.modified_properties.`0`.new_value LIKE "*Commvault*" OR azure.auditlogs.properties.target_resources.`0`.modified_properties.`0`.old_value LIKE "*Commvault*")
| EVAL
    // Bucket events by each week
    timestamp_week_bucket = DATE_TRUNC(7 day, @timestamp)
| STATS
    operation = VALUES(azure.auditlogs.operation_name),
    app_id = VALUES(azure.auditlogs.properties.additional_details.appId),
    correlation_id = VALUES(azure.auditlogs.properties.correlation_id),
    identity = VALUES(azure.auditlogs.properties.identity),
    initiated_by_id = VALUES(azure.auditlogs.properties.initiated_by.user.id),
    user_principal_name = VALUES(azure.auditlogs.properties.initiated_by.user.userPrincipalName),
    tenant_id = VALUES(azure.auditlogs.properties.tenantId),
    modified_properties_new = VALUES(azure.auditlogs.properties.target_resources.`0`.modified_properties.`0`.new_value),
    modified_properties_old = VALUES(azure.auditlogs.properties.target_resources.`0`.modified_properties.`0`.old_value),
    weekly_occurrence_count = COUNT_DISTINCT(timestamp_week_bucket)
    BY source.ip, azure.auditlogs.properties.additional_details.appId
| WHERE weekly_occurrence_count <= 5
```

## Notes

- This is an ES|QL query returning results in a tabular format. Analysts should pivot from any column value (e.g., `app_id`, `initiated_by_id`, `source.ip`, or `correlation_id`) into raw event data to inspect the full scope of the activity.
- The operation `Add service principal credentials` indicates a credential (e.g., password or certificate) was added to a service principal. This is often legitimate but can be abused for persistence, especially if the service principal was compromised or created by a threat actor.
- Investigate the value of `azure.auditlogs.properties.additional_details.appId`. Determine whether this service principal belongs to a Microsoft-managed application, a known third-party tool like Commvault, or an unknown application.
- Review `azure.auditlogs.properties.target_resources.0.display_name` or its equivalent in the raw logs to verify the name of the service principal receiving credentials.
- Examine `modified_properties_new` and `modified_properties_old` to understand how many credentials were added. Look for suspicious patterns, such as multiple credentials added at once or display names like `Commvault`.
- Pivot on the `initiated_by_id` and `user_principal_name` to determine if the activity was expected or if the account may be compromised.
- Check the `source.ip` for geolocation, VPN/proxy usage, or unfamiliar ISP origin. Uncommon IPs for specific 3rd-party service principals may indicate adversarial activity.
- A low `weekly_occurrence_count` (e.g., 1) suggests the activity is rare for the given service principal and IP, making it worthy of further investigation.
- Review activity linked via any of the `correlation_id` values to see what actions followed credential addition. This may include sign-ins, Graph API calls, or resource access.
- Search for downstream activity from the `app_id`, such as token usage, service principal logins, or cloud resource actions that may indicate abuse or persistence.

## MITRE ATT&CK Techniques

- [T1098.001](https://attack.mitre.org/techniques/T1098/001)

## References

- https://cloud.google.com/blog/topics/threat-intelligence/remediation-and-hardening-strategies-for-microsoft-365-to-defend-against-unc2452
- https://dirkjanm.io/azure-ad-privilege-escalation-application-admin/
- https://www.cisa.gov/news-events/alerts/2025/05/22/advisory-update-cyber-threat-activity-targeting-commvaults-saas-cloud-application-metallic

## License

- `Elastic License v2`

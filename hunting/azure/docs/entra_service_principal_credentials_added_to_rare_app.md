# Microsoft Entra ID Credentials Added to Rare Service Principal

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query gathers evidence of a compromised Microsoft Entra ID identity creating new credentials for a service principal. This may indicate that an attacker has hijacked an Application Administrative entity and is attempting to use it escalate privileges by adding backdoor credentials to a service principal. Service principals are often used to manage permissions and access to resources in Azure, making them a valuable target for attackers. 
- **UUID:** `d2dd0288-0a8c-11f0-b738-f661ea17fbcc`
- **Integration:** [azure](https://docs.elastic.co/integrations/azure)
- **Language:** `[ES|QL]`
- **Source File:** [Microsoft Entra ID Credentials Added to Rare Service Principal](../queries/entra_service_principal_credentials_added_to_rare_app.toml)

## Query

```sql
FROM logs-azure.auditlogs*
| WHERE
    // filter on Microsoft Entra Audit Logs
    // filter for service principal credentials being added
    event.dataset == "azure.auditlogs"
    and azure.auditlogs.operation_name == "Add service principal credentials"
    and event.outcome == "success"
| EVAL
    // SLICE n0 of requests values for specific Client App ID
    // Cast Client App ID to STRING type
    azure.auditlogs.properties.additional_details.appId = MV_SLICE(azure.auditlogs.properties.additional_details.value, 0)::STRING
| WHERE
    // REGEX on Client APP ID for UUIDv4
    azure.auditlogs.properties.additional_details.appId RLIKE """[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"""
| EVAL
    // BUCKET events weekly
    timestamp_week_bucket = DATE_TRUNC(7 day, @timestamp)
| STATS
    // Aggregate weekly occurrences by Client App ID, User ID
    weekly_user_app_occurrence_count = COUNT_DISTINCT(timestamp_week_bucket) BY
        azure.auditlogs.properties.additional_details.appId,
        azure.auditlogs.properties.initiated_by.user.id
| WHERE weekly_user_app_occurrence_count == 1
```

## Notes

- This is an ES|QL query, therefore results are returned in a tabular format. Pivot into related events using the `azure.auditlogs.properties.initiated_by.user.id`
- Review `azure.auditlogs.properties.additional_details.appId` to verify the Client App ID. This should be a known application in your environment. Check if it is an Azure-managed application, custom application, or a third-party application.
- The `azure.auditlogs.properties.additional_details.appId` value will be available in `azure.auditlogs.properties.additional_details.value` when triaging the original events.
- The `azure.auditlogs.properties.initiated_by.user.id` may be a hijacked account with elevated privileges. Review the user account to determine if it is a known administrative account or a compromised account.
- Review `azure.auditlogs.properties.target_resources.0.display_name` to verify the service principal name. This correlates directly to the `azure.auditlogs.properties.additional_details.appId` value.
- Identify potential authentication events from the service principal the credentials were added to. This may indicate that the service principal is being used to access resources in your environment.

## MITRE ATT&CK Techniques

- [T1098.001](https://attack.mitre.org/techniques/T1098/001)

## References

- https://cloud.google.com/blog/topics/threat-intelligence/remediation-and-hardening-strategies-for-microsoft-365-to-defend-against-unc2452
- https://dirkjanm.io/azure-ad-privilege-escalation-application-admin/

## License

- `Elastic License v2`

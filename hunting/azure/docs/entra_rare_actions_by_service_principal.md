# Microsoft Entra ID Rare Service Principal Activity from Multiple IPs

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies service principal activity across Microsoft Entra ID, Microsoft 365, and Graph API logs that is both rare and originates from multiple IP addresses. Adversaries may abuse service principals to persist access, move laterally, or access sensitive APIs. This hunt surfaces service principals performing unusual or infrequent actions from more than one IP, which could indicate credential misuse or stolen token replay.
- **UUID:** `91f4e8e6-7d35-45e1-89c5-8c77e78ef5c1`
- **Integration:** [azure](https://docs.elastic.co/integrations/azure), [o365](https://docs.elastic.co/integrations/o365)
- **Language:** `[ES|QL]`
- **Source File:** [Microsoft Entra ID Rare Service Principal Activity from Multiple IPs](../queries/entra_rare_actions_by_service_principal.toml)

## Query

```sql
FROM logs-azure.*, logs-o365.audit-*
| WHERE @timestamp > now() - 30 day
| WHERE
  event.dataset in ("azure.auditlogs", "azure.signinlogs", "o365.audit", "azure.graphactivitylogs")
  AND (
    (azure.signinlogs.properties.service_principal_name IS NOT NULL OR
     azure.auditlogs.properties.initiated_by.app.servicePrincipalId IS NOT NULL OR
     azure.graphactivitylogs.properties.service_principal_id IS NOT NULL) OR
    `o365`.audit.ExtendedProperties.extendedAuditEventCategory == "ServicePrincipal"
  )
| EVAL
  service_principal_name = COALESCE(
    azure.auditlogs.properties.initiated_by.app.displayName,
    azure.signinlogs.properties.service_principal_name,
    `o365`.audit.UserId
  ),
  service_principal_id = COALESCE(
    azure.auditlogs.properties.initiated_by.app.servicePrincipalId,
    azure.graphactivitylogs.properties.service_principal_id,
    `o365`.audit.UserId,
    azure.signinlogs.properties.service_principal_id
  ),
  timestamp_day_bucket = DATE_TRUNC(1 day, @timestamp)
| WHERE source.ip IS NOT NULL
// filter for unexpected service principal and IP address patterns
// OR NOT CIDR_MATCH(source.ip, "127.0.0.2/32")
| STATS
  event_count = COUNT(),
  ips = VALUES(source.ip),
  distinct_ips = COUNT_DISTINCT(source.ip),
  datasets = VALUES(event.dataset),
  service_principal_ids = VALUES(service_principal_id),
  event_actions = VALUES(event.action),
  daily_action_count = COUNT()
  BY event.action, service_principal_name, timestamp_day_bucket
| WHERE (daily_action_count <= 5 and distinct_ips >= 2)
| SORT daily_action_count ASC
```

## Notes

- This is an ES|QL query returning results in a tabular format. Analysts should pivot from any column value (e.g., `event.action`, `service_principal_name`, `service_principal_id`, or `source.ip`) into raw event data to inspect the full scope of the activity.
- This hunt looks for service principals performing rare or low-frequency actions (≤ 5 per day) from multiple IPs (≥ 2), which could indicate replayed tokens, stolen credentials, or unusual automation.
- The `service_principal_name` field is populated using the display name or user ID, depending on the log source.
- The `service_principal_id` is used to correlate actions across datasets such as Azure Audit Logs, Sign-In Logs, M365 Audit Logs, and Graph Activity Logs.
- Check the `source.ip` field for anomalies in geolocation or ASN. If the same SP is used from geographically distant locations or via unexpected ISPs, this may indicate compromise.
- Review the `event.action` field to determine what the service principal was doing — uncommon API calls, login attempts, resource creation, or changes should be reviewed.
- Rare service principal behavior may be legitimate (e.g., new integration) but should always be validated against expected automation and deployment activity.
- This technique has been observed in attacks involving abuse of OAuth apps, Microsoft Graph API access, and stolen tokens for lateral movement or persistent access.

## MITRE ATT&CK Techniques

- [T1098.001](https://attack.mitre.org/techniques/T1098/001)

## References

- https://www.cisa.gov/news-events/alerts/2025/05/22/advisory-update-cyber-threat-activity-targeting-commvaults-saas-cloud-application-metallic

## License

- `Elastic License v2`

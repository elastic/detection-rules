# Multiple Service Logging Deleted or Stopped

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies the deletion or stopping of multiple service logging actions within AWS. Service logging is a critical security control that provides visibility into the activities and changes within AWS services. Adversaries may attempt to disable or delete service logging to evade detection and cover their tracks. Monitoring for multiple service logging deletions or stops can help identify potential malicious activity and ensure that critical security controls remain intact.

- **UUID:** `d74f8928-5e46-11ef-9488-f661ea17fbce`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [Multiple Service Logging Deleted or Stopped](../queries/multiple_service_logging_deleted_or_stopped.toml)

## Query

```sql
from logs-aws.cloudtrail*
| where @timestamp > now() - 7 day
| where
    event.provider in ("ec2.amazonaws.com","route53resolver.amazonaws.com","s3.amazonaws.com", "cloudtrail.amazonaws.com")
    and event.action in ("DeleteFlowLogs","DeleteResolverQueryLogConfig", "DeleteTrail", "StopLogging")
| eval date = DATE_FORMAT("YYYY-mm-dd", @timestamp)
| stats service_logging_delete_count = count(*) by event.provider, event.action, event.outcome, date, aws.cloudtrail.user_identity.arn
```

## Notes

- Use the `event.provider` field to identify the service logging action that was deleted or stopped
- Use the `event.action` field to identify the specific action that was taken on the service logging
- Review the `aws.cloudtrail.user_identity*` fields to identify the user making the requests and their role permissions
- Review the `source.*` fields for the IP address and geographical location of the request and compare with the user's typical behavior
- Check for `CreateFlowLogs`, `CreateResolverQueryLogConfig`, `CreateTrail`, and `StartLogging` API calls to determine if the service logging was recently enabled or started. This could help determine if the deletion was due to maintence or configuration changes
- Use ES|QL `stats` function to aggregated on date to identify patterns of multiple service logging deletions or stops
- 

## MITRE ATT&CK Techniques

- [T1562.008](https://attack.mitre.org/techniques/T1562/008)

## License

- `Elastic License v2`

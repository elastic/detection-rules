# IAM Unusual Default Aviatrix Role Activity

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies unusual activity related to the default Aviatrix role in AWS CloudTrail logs. The Aviatrix role is a default role created by the Aviatrix Controller to manage AWS resources. Unusual activity may indicate unauthorized access or misuse of the Aviatrix role, potentially leading to data exfiltration, privilege escalation, or other security incidents.

- **UUID:** `9fe48b6e-d83a-11ef-84a6-f661ea17fbcd`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [IAM Unusual Default Aviatrix Role Activity](../queries/iam_unusual_default_aviatrix_role_activity.toml)

## Query

```sql
from logs-aws.cloudtrail-*
| where @timestamp > now() - 14 day
| where event.dataset == "aws.cloudtrail"
    and aws.cloudtrail.user_identity.type == "AssumedRole"
    and aws.cloudtrail.user_identity.arn like "*aviatrix-role*"
| stats activity_counts = count(*) by event.provider, event.action, aws.cloudtrail.user_identity.arn
| where activity_counts < 10
| sort activity_counts asc
```

## Notes

- Review the `aws.cloudtrail.user_identity.arn` field to identify the Aviatrix role.
- Review the `aws.cloudtrail.resources.arn` field to identify the EC2 instance associated with the activity.
- Review security group and network ACL configurations for the EC2 instance to ensure they are not overly permissive or allow unauthorized access.
- Using the EC2 instance, pivot into VPC Flow Logs to identify network traffic patterns and potential lateral movement.
- Review if the controller was recently deployed or updated, as this may explain unusual activity related to the Aviatrix role.
- If available, review endpoint logs for the Aviatrix Controller to identify any aviatrix processes that have made unusual requests or system calls.

## MITRE ATT&CK Techniques

- [T1078.004](https://attack.mitre.org/techniques/T1078/004)

## License

- `Elastic License v2`

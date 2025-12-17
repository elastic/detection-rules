# High EC2 Instance Deployment Count Attempts by Single User or Role

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies when a user makes EC2 `RunInstances` API calls with a high instance deployment count within a 7-day window. The `RunInstances` API call launches one or more instances in a specified subnet. High instance deployment counts may indicate an adversary attempting to deploy a large number of instances for cryptomining or other malicious activities. This may also aid in identifying potential resource abuse or misconfigurations.

- **UUID:** `c3d24ae8-655d-11ef-a990-f661ea17fbcc`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [High EC2 Instance Deployment Count Attempts by Single User or Role](../queries/ec2_high_instance_deployment_count_attempts.toml)

## Query

```sql
from logs-aws.cloudtrail-*
| where @timestamp > now() - 7 day
| where
    event.dataset == "aws.cloudtrail"
    and event.provider == "ec2.amazonaws.com"
    and event.action == "RunInstances"
    and aws.cloudtrail.request_parameters RLIKE ".*minCount.*maxCount.*"
| eval date = DATE_FORMAT("YYYY-mm-dd", @timestamp)
| dissect aws.cloudtrail.request_parameters "%{}subnetId=%{subnet_id},"
| dissect aws.cloudtrail.request_parameters "%{}minCount=%{min_count},"
| dissect aws.cloudtrail.request_parameters "%{}maxCount=%{max_count}}]},"
| dissect aws.cloudtrail.request_parameters "%{}instanceType=%{instance_type},"
| stats
    target_instance_count = sum(to_integer(max_count) - to_integer(min_count) + 1),
    user_attempts = count(*) by user.name, date, subnet_id, instance_type, event.outcome
| where target_instance_count >= 10
```

## Notes

- Use the `aws.cloudtrail.user_identity.arn` field to identify the user making the requests and their role permissions
- Review `cloud.region` to identify the regions where the `RunInstances` API calls were made
- `subnet_id` should be reviewed to identify the subnet where the instances are being deployed but can also help pivot and narrow down the scope of further queries
- `instance_type` should be reviewed to identify the type of instances being deployed. Cryptomining campaigns often deploy specific instance types to maximize mining efficiency

## MITRE ATT&CK Techniques

- [T1578.002](https://attack.mitre.org/techniques/T1578/002)

## License

- `Elastic License v2`

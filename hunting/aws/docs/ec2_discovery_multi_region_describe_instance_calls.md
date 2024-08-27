# High Frequency of EC2 Multi-Region `DescribeInstances` API Calls

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies when a user makes multiple `DescribeInstances` API calls in multiple regions within a 30-second window. The `DescribeInstances` API call retrieves information about one or more EC2 instances in a region. High frequency of `DescribeInstances` API calls across multiple regions may indicate an adversary attempting to discover the EC2 instances in the account or perform reconnaissance on the EC2 environment.

- **UUID:** `e6e78858-6482-11ef-93bd-f661ea17fbcc`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [High Frequency of EC2 Multi-Region `DescribeInstances` API Calls](../queries/ec2_discovery_multi_region_describe_instance_calls.toml)

## Query

```sql
from logs-aws.cloudtrail-*
| where @timestamp > now() - 7 day

// filter for DescribeInstances API calls
| where event.dataset == "aws.cloudtrail" and event.provider == "ec2.amazonaws.com" and event.action == "DescribeInstances"

// truncate the timestamp to a 30-second window
| eval target_time_window = DATE_TRUNC(30 seconds, @timestamp)

// count the number of unique regions and total API calls within the 30-second window
| stats region_count = count_distinct(cloud.region), window_count = count(*) by target_time_window, aws.cloudtrail.user_identity.arn

// filter for resources making DescribeInstances API calls in more than 10 regions within the 30-second window
| where region_count >= 10 and window_count >= 10

// sort the results by time windows in descending order
| sort target_time_window desc
```

## Notes

- Use the `aws.cloudtrail.user_identity.arn` field to identify the user making the requests and their role permissions
- Use the `cloud.region` field to identify the regions where the `DescribeInstances` API calls were made
- If leveraging SSM, query for `StartSession` API calls to determine if the user is attempting to establish a session with the EC2 instances
- Filter for `event.provider` is `ec2.amazonaws.com` to pivot on unusual activity related to EC2 instances

## MITRE ATT&CK Techniques

- [T1580](https://attack.mitre.org/techniques/T1580)

## License

- `Elastic License v2`

# High Frequency of Service Quotas Multi-Region `GetServiceQuota` API Calls

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies when a single AWS resource is making `GetServiceQuota` API calls for the EC2 service quota L-1216C47A in more than 10 regions within a 30-second window. Quota code L-1216C47A represents on-demand instances which are used by adversaries to deploy malware and mine cryptocurrency. This could indicate a potential threat actor attempting to discover the AWS infrastructure across multiple regions using compromised credentials or a compromised instance.

- **UUID:** `7a083b24-6482-11ef-8a8f-f661ea17fbcc`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [High Frequency of Service Quotas Multi-Region `GetServiceQuota` API Calls](../queries/servicequotas_discovery_multi_region_get_service_quota_calls.toml)

## Query

```sql
from logs-aws.cloudtrail-*
| where @timestamp > now() - 7 day

// filter for GetServiceQuota API calls
| where event.dataset == "aws.cloudtrail" and event.provider = "servicequotas.amazonaws.com" and event.action == "GetServiceQuota"

// truncate the timestamp to a 30-second window
| eval target_time_window = DATE_TRUNC(30 seconds, @timestamp)

// pre-process the request parameters to extract the service code and quota code
| dissect aws.cloudtrail.request_parameters "{%{?service_code_key}=%{service_code}, %{?quota_code_key}=%{quota_code}}"

// filter for EC2 service quota L-1216C47A (vCPU on-demand instances)
| where service_code == "ec2" and quota_code == "L-1216C47A"

// count the number of unique regions and total API calls within the 30-second window
| stats region_count = count_distinct(cloud.region), window_count = count(*) by target_time_window, aws.cloudtrail.user_identity.arn

// filter for resources making DescribeInstances API calls in more than 10 regions within the 30-second window
| where region_count >= 10 and window_count >= 10

// sort the results by time windows in descending order
| sort target_time_window desc
```

## Notes

- Use the `aws.cloudtrail.user_identity.arn` field to identify the user making the requests and their role permissions
- Use the `cloud.region` field to identify the regions where the `GetServiceQuota` API calls were made
- Review Elastic Defend alerts for endpoint related activity to identify potential malware or cryptocurrency mining activity
- If a valid account compromise is suspected, review source.* fields for the IP address and geographical location of the request and compare with the user's typical behavior
- Query for `RunInstances` API calls to determine if new instances were launched using the on-demand instances
- If new instances were launched, review the instance metadata and user data scripts for malicious content

## MITRE ATT&CK Techniques

- [T1580](https://attack.mitre.org/techniques/T1580)

## License

- `Elastic License v2`

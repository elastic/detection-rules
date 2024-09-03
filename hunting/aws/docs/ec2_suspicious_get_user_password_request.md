# EC2 Suspicious Get User Password Request

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies when a user makes multiple `GetPasswordData` requests for an EC2 instance. The `GetPasswordData` API call retrieves the encrypted administrator password for an instance running Windows. This API call typically only occurs during the initial launch of an instance or when the password is reset. Multiple requests for the same instance may indicate an adversary attempting to escalate privileges or move laterally within the EC2 environment.

- **UUID:** `408ba5f6-5db7-11ef-a01c-f661ea17fbce`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [EC2 Suspicious Get User Password Request](../queries/ec2_suspicious_get_user_password_request.toml)

## Query

```sql
from logs-aws.cloudtrail*
| where @timestamp > now() - 7 day
| where event.provider == "ec2.amazonaws.com" and event.action == "GetPasswordData"
| dissect aws.cloudtrail.request_parameters "{%{?instance_key}=%{instance_id}}"
| stats instance_count = count_distinct(instance_id) by aws.cloudtrail.user_identity.arn
| where instance_count >= 2
```

## Notes

- Use the `instance_id` field to identify the EC2 instance for which the `GetPasswordData` requests were made
- Check for `RunInstances` API calls to determine if the instance was recently launched or if the password was reset
- `aws.cloudtrail.error_code` can provide additional context if the `GetPasswordData` request failed or was denied
- Review the `aws.cloudtrail.user_identity*` fields to identify the user making the requests and their role permissions
- If a valid account compromise is suspected, review source.* fields for the IP address and geographical location of the request and compare with the user's typical behavior

## MITRE ATT&CK Techniques

- [T1552.005](https://attack.mitre.org/techniques/T1552/005)

## License

- `Elastic License v2`

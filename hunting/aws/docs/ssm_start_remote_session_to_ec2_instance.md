# SSM Start Remote Session to EC2 Instance

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies when a user starts a remote session to an EC2 instance using the AWS Systems Manager (SSM) service. The `StartSession` API call allows users to connect to an EC2 instance using the SSM service. Multiple `StartSession` requests to the same EC2 instance may indicate an adversary attempting to gain access to the instance for malicious purposes. By default on certain AMI types, the SSM agent is pre-installed and running, allowing for easy access to the instance without the need for SSH or RDP.

- **UUID:** `f9eae44e-5e4d-11ef-878f-f661ea17fbce`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [SSM Start Remote Session to EC2 Instance](../queries/ssm_start_remote_session_to_ec2_instance.toml)

## Query

```sql
from logs-aws.cloudtrail-*
| where @timestamp > now() - 7 day
| where event.provider == "ssm.amazonaws.com" and event.action == "StartSession"
| dissect aws.cloudtrail.request_parameters "{%{target_key}=%{target_instance}}"
| stats user_instance_counts = count(*) by target_instance, aws.cloudtrail.user_identity.arn, aws.cloudtrail.user_identity.type, event.outcome
```

## Notes

- Use the `target_instance` field to identify the EC2 instance that the user connected to using the SSM service
- Review the `aws.cloudtrail.user_identity*` fields to identify the user making the requests and their role permissions
- The `event.outcome` field can provide additional context on the success or failure of the `StartSession` request
- Identify if the EC2 instance was recently launched by filtering `event.action` field for `RunInstances` API calls. If the instance was not recently launched, investigate further
- Sessions started from IAM users may be benign, but sessions where the `aws.cloudtrail.user_identity.type` is `AssumedRole` are suspicious as they indicate instance to instance connections.

## MITRE ATT&CK Techniques

- [T1021.007](https://attack.mitre.org/techniques/T1021/007)

## License

- `Elastic License v2`

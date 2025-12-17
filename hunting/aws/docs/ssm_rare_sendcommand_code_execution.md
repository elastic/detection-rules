# SSM Rare SendCommand Code Execution by EC2 Instance

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies when a single `SendCommand` API call is made by an EC2 instance to execute a command via the AWS Systems Manager (SSM) service within the last 7 days. The `SendCommand` API call allows users to remotely execute commands on EC2 instances. Default documents like `AWS-RunPowerShellScript` and `AWS-RunShellScript` are commonly used for this purpose. Adversaries may abuse this API to execute arbitrary commands on compromised EC2 instances.

- **UUID:** `1844f2d6-5dc7-11ef-b76c-f661ea17fbce`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [SSM Rare SendCommand Code Execution by EC2 Instance](../queries/ssm_rare_sendcommand_code_execution.toml)

## Query

```sql
from logs-aws.cloudtrail-*
| where @timestamp > now() - 7 day
| where event.provider == "ssm.amazonaws.com" and event.action == "SendCommand"
| dissect aws.cloudtrail.request_parameters "%{}documentName=%{document_name},%{}"
| dissect aws.cloudtrail.response_elements "%{}instanceIds=[%{instance_id}],%{}"
| where document_name in ("AWS-RunPowerShellScript","AWS-RunShellScript") and instance_id != "*"
| stats user_command_counts = count(*) by instance_id
| where user_command_counts == 1
```

## Notes

- With count 1, this rule will only trigger once for each unique value of the `instance_id` field that has not been seen making this API request within the last 7 days.
- Use the `instance_id` field to identify the EC2 instance that executed the command. This instance ID can be used to search for all related activities, focusing on `event.action` and `aws.cloudtrail.request_parameters` fields.
- The `parameter` field in the `aws.cloudtrail.request_parameters` contains the command executed by the EC2 instance, however is masked in the query to prevent sensitive data exposure by AWS. Reviewing commands executed on the instance can provide context on the adversary's actions.

## MITRE ATT&CK Techniques

- [T1651](https://attack.mitre.org/techniques/T1651)

## License

- `Elastic License v2`

# EC2 Modify Instance Attribute User Data

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies when a user modifies the user data attribute of an EC2 instance. The user data attribute is a script that runs when the instance is launched. Modifying the user data attribute could indicate an adversary attempting to gain persistence or execute malicious code on the instance.

- **UUID:** `f11ac62c-5f42-11ef-9d72-f661ea17fbce`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [EC2 Modify Instance Attribute User Data](../queries/ec2_modify_instance_attribute_user_data.toml)

## Query

```sql
from logs-aws.cloudtrail-*
| where @timestamp > now() - 7 day
| where
    event.provider == "ec2.amazonaws.com"
    and event.action == "ModifyInstanceAttribute"
    and aws.cloudtrail.request_parameters RLIKE ".*attribute=userData.*"
| dissect aws.cloudtrail.request_parameters "{%{instance_id_key}=%{instance_id}, %{attribute_key}=%{attribute}, %{value_key}=%{value}}"
| stats user_attribute_modify_count = count(*) by aws.cloudtrail.user_identity.arn, event.outcome
```

## Notes

- Use the `instance_id` field to identify the EC2 instance for which the user data attribute was modified
- Pivot into the EC2 instance if possible and examine the user data script ('/var/lib/cloud/instance/scripts/userdata.txt') for malicious content
- To modify an EC2 instance's user data attribute, the instance must be stopped, therefore check for `StopInstances` API calls in `event.action` field to determine if the instance was stopped and started
- AWS redacts the value of the `user_data` attribute in the CloudTrail logs, so the actual script content will not be visible in the logs

## MITRE ATT&CK Techniques

- [T1059.009](https://attack.mitre.org/techniques/T1059/009)
- [T1037](https://attack.mitre.org/techniques/T1037)

## License

- `Elastic License v2`

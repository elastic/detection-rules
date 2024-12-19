# SSM SendCommand API Used by EC2 Instance

---

## Metadata

- **Author:** Elastic
- **Description:** An attacker with compromised EC2 instance credentials, may use those credentials to attempt remote code execution against the EC2 instance from which the credentials were compromised via SSM SendCommand API.

- **UUID:** `38454a64-5b55-11ef-b345-f661ea17fbce`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [SSM SendCommand API Used by EC2 Instance](../queries/ssm_sendcommand_api_used_by_ec2_instance.toml)

## Query

```sql
from logs-aws.cloudtrail-*
| where @timestamp > now() - 7 day
| where event.dataset == "aws.cloudtrail"
    and event.provider == "ssm.amazonaws.com"
    and aws.cloudtrail.user_identity.type == "AssumedRole"
    and event.action == "SendCommand"
    and user.id like "*:i-*"
| keep @timestamp, event.provider, event.action, aws.cloudtrail.user_identity.type, user.id, aws.cloudtrail.request_parameters
```

## Notes

- The indicator that this is an EC2 instance assuming a role and performing the action, is the use of the instance id beginning with -i as the session name.
- Session name is attached to the end of the `user.id` field and the `aws.cloudtrail.user_identity.arn`.

## MITRE ATT&CK Techniques

- [T1651](https://attack.mitre.org/techniques/T1651)

## License

- `Elastic License v2`

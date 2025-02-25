# SNS Topic Message Published by Rare User

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query gathers evidence of an SNS topic message published by a user who does not typically perform this action. Adversaries may publish messages to SNS topics to stage capabilities for data exfiltration or other malicious activities.

- **UUID:** `db405900-e955-11ef-8c29-f661ea17fbce`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [SNS Topic Message Published by Rare User](../queries/sns_topic_message_published_by_rare_user.toml)

## Query

```sql
from logs-aws.cloudtrail-*
| where @timestamp > now() - 7 day
| WHERE
    event.dataset == "aws.cloudtrail" AND
    event.provider == "sns.amazonaws.com" AND
    event.action == "Publish"
    and aws.cloudtrail.user_identity.type == "AssumedRole"
| DISSECT aws.cloudtrail.request_parameters "{%{?message_key}=%{message}, %{?topic_key}=%{topic_arn}}"
| DISSECT aws.cloudtrail.user_identity.arn "%{?}:assumed-role/%{assumed_role_name}/%{entity}"
| DISSECT user_agent.original "%{user_agent_name} %{?user_agent_remainder}"
| WHERE STARTS_WITH(entity, "i-")
| STATS regional_topic_publish_count = COUNT(*) by cloud.account.id, entity, assumed_role_name, topic_arn, cloud.region, user_agent_name
| SORT regional_topic_publish_count ASC
```

## Notes

- If a user identity access key (`aws.cloudtrail.user_identity.access_key_id`) exists in the CloudTrail audit log, then this request was accomplished via the CLI or programmatically. These keys could be compromised and warrant further investigation.
- If you notice Terraform, Pulumi, etc. it may be related to testing environments, maintenance or more.
- Python SDKs that are not AWS, may indicate custom tooling or scripts being leveraged.

## MITRE ATT&CK Techniques

- [T1567](https://attack.mitre.org/techniques/T1567)
- [T1566.003](https://attack.mitre.org/techniques/T1566/003)

## License

- `Elastic License v2`

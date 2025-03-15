# SNS Topic Created by Rare User

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query gathers evidence of an SNS topic created by a user who does not typically perform this action. Adversaries may create SNS topics to stage capabilities for data exfiltration or other malicious activities.

- **UUID:** `80955fb2-e952-11ef-b7cc-f661ea17fbce`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [SNS Topic Created by Rare User](../queries/sns_topic_created_by_rare_user.toml)

## Query

```sql
from logs-aws.cloudtrail-*
| WHERE @timestamp > now() - 7 day
| WHERE
    event.dataset == "aws.cloudtrail" AND
    event.provider == "sns.amazonaws.com" AND
    event.action == "CreateTopic"
    and aws.cloudtrail.user_identity.type == "AssumedRole"
| DISSECT aws.cloudtrail.request_parameters "{%{?topic_name_key}=%{topic_name}}"
| DISSECT aws.cloudtrail.user_identity.arn "%{?}:assumed-role/%{assumed_role_name}/%{entity}"
| DISSECT user_agent.original "%{user_agent_name} %{?user_agent_remainder}"
| WHERE STARTS_WITH(entity, "i-")
| STATS regional_topic_created_count = COUNT(*) by cloud.account.id, entity, assumed_role_name, cloud.region, user_agent_name
| SORT regional_topic_created_count ASC
```

## Notes

- It is unusual for credentials from an assumed role for an EC2 instance to be creating SNS topics randomly.
- If a user identity access key (`aws.cloudtrail.user_identity.access_key_id`) exists in the CloudTrail audit log, then this request was accomplished via the CLI or programmatically. These keys could be compromised and warrant further investigation.
- Pivot into `Publish` API actions being called to this specific topic to identify which AWS resource is publishing messages. With access to the topic, you could further investigate the subscribers list to identify unauthorized subscribers.

## MITRE ATT&CK Techniques

- [T1608](https://attack.mitre.org/techniques/T1608)

## License

- `Elastic License v2`

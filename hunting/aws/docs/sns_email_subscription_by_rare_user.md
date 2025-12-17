# SNS Topic Subscription with Email by Rare User

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query gathered evidence of an SNS topic subscribed to by an email address of a user who does not typically perform this action. Adversaries may subscribe to SNS topics to collect sensitive information or exfiltrate data via an external email address.

- **UUID:** `fb752e42-e952-11ef-85e7-f661ea17fbce`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [SNS Topic Subscription with Email by Rare User](../queries/sns_email_subscription_by_rare_user.toml)

## Query

```sql
from logs-aws.cloudtrail-*
| where @timestamp > now() - 7 day
| WHERE
    event.dataset == "aws.cloudtrail" AND
    event.provider == "sns.amazonaws.com" AND
    event.action == "Subscribe"
| DISSECT aws.cloudtrail.request_parameters "%{?protocol_key}=%{protocol}, %{?endpoint_key}=%{redacted}, %{?return_arn}=%{return_bool}, %{?topic_arn_key}=%{topic_arn}}"
| DISSECT user_agent.original "%{user_agent_name} %{?user_agent_remainder}"
| WHERE protocol == "email"
| STATS regional_topic_subscription_count = COUNT(*) by aws.cloudtrail.user_identity.arn, cloud.region, source.address, user_agent_name
| WHERE regional_topic_subscription_count == 1
| SORT regional_topic_subscription_count ASC
```

## Notes

- If a user identity access key (aws.cloudtrail.user_identity.access_key_id) exists in the CloudTrail audit log, then this request was accomplished via the CLI or programmatically. These keys could be compromised and warrant further investigation.
- Ignoring the topic ARN during aggregation is important to identify first occurrence anomalies of subscribing to SNS topic with an email.
- Another query may be required with the user identity arn as an inclusion filter to identify which topic they subscribed to.

## MITRE ATT&CK Techniques

- [T1567](https://attack.mitre.org/techniques/T1567)
- [T1530](https://attack.mitre.org/techniques/T1530)

## License

- `Elastic License v2`

# SNS Direct-to-Phone Messaging Spike

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query gathers evidence of potential abuse of the SNS service to send direct-to-phone text messages. Adversaries may use this technique to send smishing messages or deliver other types of malicious content directly to users' phones.

- **UUID:** `21e4d0ee-e955-11ef-8c29-f661ea17fbce`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [SNS Direct-to-Phone Messaging Spike](../queries/sns_direct_to_phone_messaging_spike.toml)

## Query

```sql
from logs-aws.cloudtrail-*
| WHERE @timestamp > now() - 7 day
| EVAL target_time_window = DATE_TRUNC(10 seconds, @timestamp)
| WHERE
    event.dataset == "aws.cloudtrail" AND
    event.provider == "sns.amazonaws.com" AND
    event.action == "Publish" AND
    event.outcome == "success" AND
    aws.cloudtrail.request_parameters LIKE "*phoneNumber*"
| DISSECT user_agent.original "%{user_agent_name} %{?user_agent_remainder}"
| STATS sms_message_count = COUNT(*) by target_time_window, cloud.account.id, aws.cloudtrail.user_identity.arn, cloud.region, source.address, user_agent_name
| WHERE sms_message_count > 30
```

## Notes

- AWS removes phone numbers in logs, so deeper analysis via CloudWatch logs may be necessary.
- While investigating in CloudWatch, the message context is also sanitized. It would be ideal to investigate the message for any suspicious URL links being embedded in the text messages.
- You can also review AWS SNS delivery logs (if enabled) for message metadata.
- If messages are not using a topic-based subscription, it suggests direct targeting.
- The source of these requests is important, if you notice them from an EC2 instance, that is rather odd or Lambda may be an expected serverless code
- Review if `aws.cloudtrail.user_identity.access_key_id` exists in the CloudTrail audit log, then this request was accomplished via the CLI or programmatically. These keys could be compromised and warrant further investigation.
- If direct SMS messages are common in your environment, you can adjust the threshold accordingly.

## MITRE ATT&CK Techniques

- [T1660](https://attack.mitre.org/techniques/T1660)

## License

- `Elastic License v2`

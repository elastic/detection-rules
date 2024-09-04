# Secrets Manager High Frequency of Programmatic GetSecretValue API Calls

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies when a high frequency of `GetSecretValue` API calls are made to the AWS Secrets Manager service programmatically. The `GetSecretValue` API call retrieves the secret value for a specified secret. High frequency of these calls may indicate an adversary attempting to access sensitive information stored in AWS Secrets Manager via a compromised account or automated tooling.

- **UUID:** `ef244ca0-5e32-11ef-a8d3-f661ea17fbce`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [Secrets Manager High Frequency of Programmatic GetSecretValue API Calls](../queries/secretsmanager_high_frequency_get_secret_value.toml)

## Query

```sql
from logs-aws.cloudtrail*
| where @timestamp > now() - 7 day
| where
    event.provider == "secretsmanager.amazonaws.com"
    and event.action == "GetSecretValue"
    and user_agent.name not in ("Chrome","Firefox","Safari", "Edge", "Brave", "Opera")
| dissect aws.cloudtrail.request_parameters "%{}secret:%{secret_value}}"
| stats request_counts = count(*) by event.action, aws.cloudtrail.user_identity.arn, source.ip, user_agent.name
| sort request_counts asc
```

## Notes

- Use the `secret_value` field to identify the secret value that was accessed by adding it to the `stats` statement
- Review the `aws.cloudtrail.user_identity*` fields to identify the user making the requests and their role permissions
- `user_agent.name` field can provide additional context on the tool or application making the API calls. If not `aws-sdk` or known application, investigate further.
- Review the `source.*` fields for the IP address and geographical location of the request and compare with the user's typical behavior
- The `aws.cloudtrail.user_identity.arn` field can provide additional context on the user making the request and their role permissions. Recent changes to role permissions or unusual logins may indicate a compromised account
- `user_agent.name` field can provide additional context on the tool or application making the API calls. If not `aws-sdk` or known application, investigate further.

## MITRE ATT&CK Techniques

- [T1555.006](https://attack.mitre.org/techniques/T1555/006)

## License

- `Elastic License v2`

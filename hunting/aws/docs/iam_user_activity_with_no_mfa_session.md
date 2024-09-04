# IAM User Activity with No MFA Session

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query gathers data for evidence of an IAM user activity with no MFA session. This query identifies IAM user activity where the user is not MFA authenticated. Adversaries often target IAM users with weak or no MFA protection to gain unauthorized access to AWS resources after compromising the user's credentials via phishing, third-party breaches, or brute-forcing.

- **UUID:** `913a47be-649c-11ef-a693-f661ea17fbcc`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [IAM User Activity with No MFA Session](../queries/iam_user_activity_with_no_mfa_session.toml)

## Query

```sql
from logs-aws.cloudtrail-*
| where @timestamp > now() - 7 day
| where event.dataset == "aws.cloudtrail"
    and aws.cloudtrail.user_identity.type == "IAMUser"
    and aws.cloudtrail.user_identity.session_context.mfa_authenticated == "false"
    and not user_agent.original in ("cloudformation.amazonaws.com", "application-autoscaling.amazonaws.com", "AWS Internal")
    and (aws.cloudtrail.user_identity.access_key_id is null or aws.cloudtrail.user_identity.access_key_id == "")
| stats activity_counts = count(*) by event.provider, event.action, aws.cloudtrail.user_identity.arn
```

## Notes

- Review the `user_identity.arn` field to identify if activity is sourcing from a browser or programmatically via the AWS CLI or SDK.
- Review aggregated counts of API calls made for suspicious discovery or reconnaissance such as `List*`, `Describe*`, or `Get*` API calls.

## MITRE ATT&CK Techniques

- [T1078.004](https://attack.mitre.org/techniques/T1078/004)

## License

- `Elastic License v2`

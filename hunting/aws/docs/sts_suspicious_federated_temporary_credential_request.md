# STS Suspicious Federated Temporary Credential Request

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies when a user requests temporary federated credentials with a duration greater than 24 hours or with the `AdministratorAccess` policy attached. Federated users are typically given temporary credentials to access AWS services. A duration greater than 24 hours or the `AdministratorAccess` policy attached may indicate an adversary attempting to maintain access to AWS services for an extended period of time or escalate privileges.

- **UUID:** `3f8393b2-5f0b-11ef-8a25-f661ea17fbce`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [STS Suspicious Federated Temporary Credential Request](../queries/sts_suspicious_federated_temporary_credential_request.toml)

## Query

```sql
from logs-aws.cloudtrail-*
| where @timestamp > now() - 7 day
| where
    event.dataset == "aws.cloudtrail"
    and event.provider == "sts.amazonaws.com"
    and event.action == "GetFederationToken"
| dissect aws.cloudtrail.request_parameters "{%{}name=%{user_name},"
| dissect aws.cloudtrail.request_parameters "{%{}durationSeconds=%{duration_requested},"
| dissect aws.cloudtrail.request_parameters "{%{}policyArns=[%{policies_applied}]"
| eval duration_minutes = to_integer(duration_requested) / 60
| where (duration_minutes > 1440) or (policies_applied RLIKE ".*AdministratorAccess.*")
| keep @timestamp, event.dataset, event.provider, event.action, aws.cloudtrail.request_parameters, user_name, duration_requested, duration_minutes, policies_applied
```

## Notes

- If the `aws.cloudtrail.user_identity.arn` does not match the `user_name` field, this may indicate an adversary attempting to escalate privileges by requesting temporary credentials for a different user.
- Review `event.outcome` field to identify if the request was successful or failed.
- The `aws.cloudtrail.user_identity.session_context.session_issuer.arn` field represents the ARN of the IAM entity that created the federated session. This IAM entity could be compromised and used to create federated sessions. This could indicate the compromised credentials or role used to create the federated session.
- An additional query for `event.provider` being `signin.amazonaws.com` and `event.action` being `GetSigninToken` can be used to identify if the temporary credentials are being exchanged for console access.

## MITRE ATT&CK Techniques

- [T1550.001](https://attack.mitre.org/techniques/T1550/001)

## License

- `Elastic License v2`

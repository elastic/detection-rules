# IAM Assume Role Creation with Attached Policy

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query gathers data for evidence of an adversary creating an IAM role with an inline attached policy that allows the role to assume another role. This only identifies flags for AWS account IDs that are different from the account ID where the role is being created indicating a potential backdoor IAM role.

- **UUID:** `429824b6-60b2-11ef-b0a4-f661ea17fbce`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [IAM Assume Role Creation with Attached Policy](../queries/iam_assume_role_creation_with_attached_policy.toml)

## Query

```sql
from logs-aws.cloudtrail-*
| where @timestamp > now() - 7 day
| where
    event.provider == "iam.amazonaws.com"
    and event.action == "CreateRole"
    and aws.cloudtrail.request_parameters RLIKE ".*Allow.*"
    and aws.cloudtrail.request_parameters RLIKE ".*sts:AssumeRole.*"
    and aws.cloudtrail.request_parameters RLIKE ".*assumeRolePolicyDocument.*"
    and aws.cloudtrail.request_parameters RLIKE ".*arn:aws:iam.*"
| dissect aws.cloudtrail.request_parameters "%{}AWS\": \"arn:aws:iam::%{target_account_id}:"
| where cloud.account.id != target_account_id
```

## Notes

- Review the `target_account_id` field to identify the account that the role is being created in. This could be another AWS account your organization owns.
- Review `aws.cloudtrail.request_parameters` to identify the role being created and the policy being attached. If the inline policy includes overly permissive permissions such as `AdministratorAccess`, this could be a sign of malicious activity.
- Pivot for `event.action` where the value is `AttachRolePolicy` to identify the policy being attached to the role.

## MITRE ATT&CK Techniques

- [T1098.003](https://attack.mitre.org/techniques/T1098/003)

## License

- `Elastic License v2`

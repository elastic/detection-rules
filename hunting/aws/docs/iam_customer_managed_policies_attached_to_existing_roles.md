# AWS IAM Customer-Managed Policy Attachment to Existing Roles

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies instances where customer-managed IAM policies are attached to existing roles, potentially indicating a privilege escalation attempt. By detecting unexpected actors attaching customer-managed policies with elevated permissions to roles, this query helps identify potential abuse or misuse within AWS. Adversaries may attach these policies to gain unauthorized permissions or enable lateral movement and persistence within the environment.

- **UUID:** `418baaf2-9ae1-11ef-be63-f661ea17fbcd`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [AWS IAM Customer-Managed Policy Attachment to Existing Roles](../queries/iam_customer_managed_policies_attached_to_existing_roles.toml)

## Query

```sql
from logs-aws.cloudtrail*
| where
    event.dataset == "aws.cloudtrail"
    and event.provider == "iam.amazonaws.com"
    and event.action == "AttachRolePolicy"
    and event.outcome == "success"
| dissect aws.cloudtrail.request_parameters "{%{}::%{owner}:%{?policy_key}/%{attached_policy_name}, %{?role_name_key}=%{target_role_name}}"
| where owner != "aws"
| stats
    actor_attaching_role_count = count(*) by aws.cloudtrail.user_identity.arn, attached_policy_name, target_role_name
```

## Notes

- Review the `attached_policy_name` and `target_role_name` fields to identify the customer-managed policy and role involved in the attachment.
- Review the permissions of the attached policy to determine the potential impact of the privilege escalation attempt.
- Review all entities that `target_role_name` may be attached to as these entities may have been compromised or misused.
- Consider reviewing the `aws.cloudtrail.user_identity.arn` field to identify the actor responsible for the privilege escalation attempt.
- Review the user agent of the actor to determine the source of the privilege escalation attempt, such as an AWS CLI or SDK.

## MITRE ATT&CK Techniques

- [T1548.005](https://attack.mitre.org/techniques/T1548/005)

## License

- `Elastic License v2`

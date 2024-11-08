# AWS IAM Customer-Managed Policy Attachment for Privilege Escalation

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies instances where customer-managed IAM policies are attached to existing roles, potentially indicating a privilege escalation attempt. By detecting unexpected actors attaching customer-managed policies with elevated permissions to roles, this query helps identify potential abuse or misuse within AWS. Adversaries may attach these policies to gain unauthorized permissions or enable lateral movement and persistence within the environment.

- **UUID:** `418baaf2-9ae1-11ef-be63-f661ea17fbcd`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [AWS IAM Customer-Managed Policy Attachment for Privilege Escalation](../queries/iam_customer_managed_policies_attached_to_existing_roles.toml)

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

- Review the `target_account_id` field to verify the AWS account in which the role is being modified, especially if this account is outside of your organization’s typical accounts.
- Examine `aws.cloudtrail.request_parameters` for details on the role and attached policy. Customer-managed policies granting overly permissive access, such as `AdministratorAccess`, may signal unauthorized privilege escalation.
- Cross-reference `event.action` values where `AttachRolePolicy` appears to further investigate attached policies that could enable lateral movement or persistence.
- Evaluate `aws.cloudtrail.user_identity.arn` to confirm if the actor attaching the policy has legitimate permissions for this action. Anomalous or unauthorized actors may indicate privilege abuse.
- Look for patterns of multiple `AttachRolePolicy` actions across roles by the same user or entity. High frequency of these actions could suggest an attempt to establish persistent control across roles within your AWS environment.

## MITRE ATT&CK Techniques

- [T1548.005](https://attack.mitre.org/techniques/T1548/005)

## License

- `Elastic License v2`

# User Creation with Administrator Policy Assigned

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query gathers data for evidence of an adversary creating a user in AWS and then assigning administrative rights to that user. The `CreateUser` API call to IAM allows the adversary to create the user and then `AttachUserPolicy` where `policy/AdministratorAccess` is identified should match attempts to assign administrative privileges.

- **UUID:** `696c3f40-5b54-11ef-b9df-f661ea17fbce`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [User Creation with Administrator Policy Assigned](../queries/iam_user_creation_with_administrator_policy_assigned.toml)

## Query

```sql
from logs-aws.cloudtrail-*
| where @timestamp > now() - 7 day
| where event.dataset == "aws.cloudtrail"
    and event.provider == "iam.amazonaws.com"
    and event.outcome == "success"
    and (event.action == "CreateUser" or
        (event.action == "AttachUserPolicy" and aws.cloudtrail.request_parameters rlike ".*AdministratorAccess.*"))
| stats unique_action_count = count_distinct(event.action) by user.target.name
| where unique_action_count == 2
```

## Notes

- `aws.cloudtrail.request_parameters` contains the target user the policy is being attached to or the user being created
- `count_distinct` ensures that the user was just created, but also had the administrative policy attached within the respective time window
- There is a chance that timestamps could be out-of-order based on ingestion and event generation in AWS CloudTrail
- The target user's IAM policies should be reviewed to ensure MFA is enabled
- Reviewing the AWS ARN in the event should identify which user made these changes; this user ID should be used to pivot into potential valid account compromise

## MITRE ATT&CK Techniques

- [T1098.003](https://attack.mitre.org/techniques/T1098/003)
- [T1136.003](https://attack.mitre.org/techniques/T1136/003)

## License

- `Elastic License v2`

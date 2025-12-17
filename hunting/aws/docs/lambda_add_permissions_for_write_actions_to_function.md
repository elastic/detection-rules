# Lambda Add Permissions for Write Actions to Function

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query gathers data for evidence of an adversary adding permissions to a Lambda function that allows write actions. The `AddPermission` API call to Lambda allows the adversary to add permissions to a Lambda function. This query identifies when the `AddPermission` API call is used to add permissions that allow write actions to a Lambda function. Adversaries may use this technique to grant themselves additional permissions to write to a Lambda function, which could be used to execute malicious code or exfiltrate data.

- **UUID:** `e3206d1c-64a9-11ef-a642-f661ea17fbcc`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [Lambda Add Permissions for Write Actions to Function](../queries/lambda_add_permissions_for_write_actions_to_function.toml)

## Query

```sql
from logs-aws.cloudtrail-*
| where @timestamp > now() - 7 day
| where
    event.dataset == "aws.cloudtrail"
    and event.provider == "lambda.amazonaws.com"
    and event.action RLIKE "AddPermission.*"
| dissect aws.cloudtrail.request_parameters "{%{?principal_key}=%{principal_id}, %{?function_name_key}=%{function_name}, %{?statement_key}=%{statement_value}, %{?action_key}=lambda:%{action_value}}"
| eval write_action = (starts_with(action_value, "Invoke") or starts_with("Update", action_value) or starts_with("Put", action_value))
| where write_action == true
| keep @timestamp, principal_id, event.provider, event.action, aws.cloudtrail.request_parameters, principal_id, function_name, action_value, statement_value, write_action
```

## Notes

- Analyze the `principal_id` to identify the entity that the permission is being granted to. Adversaries may use this technique to grant themselves additional permissions.
- Review the `function_name` to identify the Lambda function that the permission is being added to.
- Identify the `action_value` to determine the type of action that the permission allows. Write actions may include `Invoke`, `Update`, or `Put`.
- 

## MITRE ATT&CK Techniques

- [T1584.007](https://attack.mitre.org/techniques/T1584/007)

## License

- `Elastic License v2`

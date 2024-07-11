# Scheduled Tasks Creation for Unique Hosts by Task Command

---

## Metadata

- **Author:** Elastic
- **Description:** Using aggregation and strings extraction, this hunt identifies instances where a scheduled task is created and set to run a command unique to a specific host. This could be the result of persistence as a Windows Scheduled Task.

- **UUID:** `44223fd6-8241-4c21-9d54-21201fa15b12`
- **Integration:** [system](https://docs.elastic.co/integrations/system)
- **Language:** `[ES|QL]`
- **Source File:** [Scheduled Tasks Creation for Unique Hosts by Task Command](../queries/scheduled_tasks_creation_for_unique_hosts_by_task_command.toml)

## Query

```sql
from logs-system.security-default-*
| where  @timestamp > now() - 7 day
| where host.os.family == "windows" and event.code == "4698" and event.action == "scheduled-task-created"
 /* parsing unstructured data from winlog message to extract a scheduled task Exec command */
| grok message "(?<Command><Command>.+</Command>)" | eval Command = replace(Command, "(<Command>|</Command>)", "")
| where Command is not null
 /* normalise task name by removing usersid and uuid string patterns */
| eval TaskName = replace(winlog.event_data.TaskName, """((-S-1-5-.*)|\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\})""", "")
 /* normalise task name by removing random patterns in a file path */
| eval Task_Command = replace(Command, """(ns[a-z][A-Z0-9]{3,4}\.tmp|DX[A-Z0-9]{3,4}\.tmp|7z[A-Z0-9]{3,5}\.tmp|[0-9\.\-\_]{3,})""", "")
 /* normalize user home profile path */
| eval Task_Command = replace(Task_Command, """[cC]:\\[uU][sS][eE][rR][sS]\\[a-zA-Z0-9\.\-\_\$~]+\\""", "C:\\\\users\\\\user\\\\")
| where Task_Command like "?*" and not starts_with(Task_Command, "C:\\Program Files") and not starts_with(Task_Command, "\"C:\\Program Files")
| stats tasks_count = count(*), hosts_count = count_distinct(host.id) by Task_Command, TaskName
| where hosts_count == 1
```

## Notes

- This hunt returns the aggregation of created tasks by task name, command to execute and number of hosts where this task is present.
- Close attention should be paid to suspicious paths like `C:\Users\Public and C:\ProgramData\` as well as LOLBins.

## MITRE ATT&CK Techniques

- [T1053](https://attack.mitre.org/techniques/T1053)
- [T1053.005](https://attack.mitre.org/techniques/T1053/005)

## License

- `Elastic License v2`

# Hidden Process Execution

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies hidden process executions on Linux systems. It detects processes executed from hidden files, which are often used by malicious actors to conceal their activities. By focusing on hidden files rather than directories, this hunt aims to catch stealthy processes while minimizing noise.

- **UUID:** `00461198-9a2d-4823-b4cc-f3d1b5c17935`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL]`
- **Source File:** [Hidden Process Execution](../queries/defense_evasion_via_hidden_process_execution.toml)

## Query

```sql
from logs-endpoint.events.process-*
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.type == "start" and event.action == "exec" and 
  process.executable rlike "/[^/]+/\\.[^/]+"
| stats cc = count(), host_count = count_distinct(host.name) by process.executable, process.parent.executable, user.id
// Alter this threshold to make sense for your environment
| where cc <= 3 and host_count <= 3
| sort cc asc
| limit 100
```

## Notes

- Included only hidden files, excluding hidden directories, as hidden directories are common in Unix.
- Included a process or parent process count of <= 3, and a host count of <= 3 to eliminate common processes across different hosts.

## MITRE ATT&CK Techniques

- [T1036.004](https://attack.mitre.org/techniques/T1036/004)
- [T1059](https://attack.mitre.org/techniques/T1059)

## License

- `Elastic License v2`

# Potential Defense Evasion via Multi-Dot Process Execution

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies potential defense evasion techniques via multi-dot process execution on Linux systems. It looks for processes with executables that contain three or more consecutive dots in their names. Such naming conventions can be used by malicious actors to evade detection and blend in with legitimate processes.

- **UUID:** `11810497-8ce3-4960-9777-9d0e97052682`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL]`
- **Source File:** [Potential Defense Evasion via Multi-Dot Process Execution](../queries/defense_evasion_via_multi_dot_process_execution.toml)

## Query

```sql
from logs-endpoint.events.process-*
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.executable rlike """.*\.{3,}.*"""
| stats cc = count() by process.executable
// Alter this threshold to make sense for your environment
| where cc <= 10
| sort cc asc
| limit 100
```

## Notes

- This query identifies processes with executables containing three or more consecutive dots in their names.
- The process count threshold of <= 10 can be adjusted based on the environment's baseline activity.

## MITRE ATT&CK Techniques

- [T1036.004](https://attack.mitre.org/techniques/T1036/004)
- [T1070](https://attack.mitre.org/techniques/T1070)

## License

- `Elastic License v2`

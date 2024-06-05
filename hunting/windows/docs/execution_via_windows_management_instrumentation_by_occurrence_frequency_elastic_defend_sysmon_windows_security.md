# Execution via Windows Management Instrumentation by occurrence frequency - Elastic Defend - Sysmon - Windows Security

---

## Metadata

- **Author:** Elastic
- **UUID:** `793d5655-d7d9-422a-ba9d-1fa75029265e`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [windows](https://docs.elastic.co/integrations/windows), [system](https://docs.elastic.co/integrations/system)
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.process-*, logs-windows.sysmon_operational-*, logs-system.security-*
| where  @timestamp > now() - 7 day and 
  host.os.family == "windows" and event.category == "process" and 
  event.action in ("start", "Process creation", "created-process") and 
  process.parent.name.caseless == "wmiprvse.exe" 
| keep process.command_line, host.id
| eval cmdline = replace(process.command_line, """[cC]:\\[uU][sS][eE][rR][sS]\\[a-zA-Z0-9\.\-\_\$~ ]+\\""", "C:\\\\users\\\\user\\\\")
| eval cmdline = replace(cmdline, """([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|ns[a-z][A-Z0-9]{3,4}\.tmp|DX[A-Z0-9]{3,4}\.tmp|7z[A-Z0-9]{3,5}\.tmp|[0-9\.\-\_]{3,})""", "")
| stats agents = count_distinct(host.id) by cmdline
| where agents == 1
```

## Notes

- This hunt looks for unique process execution via Windows Management Instrumentation by removing random patterns from process.command_line and aggregating execution by count of agents with same cmdline to limit result to unique ones.
- This hunt is compatible with Sysmon, Elastic Defend and Windows Security event 4688.
## MITRE ATT&CK Techniques

- [T1047](https://attack.mitre.org/techniques/T1047)

## License

- `Elastic License v2`

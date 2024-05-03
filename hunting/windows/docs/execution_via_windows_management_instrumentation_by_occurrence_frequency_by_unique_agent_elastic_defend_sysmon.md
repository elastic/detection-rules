# Execution via Windows Management Instrumentation by occurrence frequency by Unique Agent - Elastic Defend - Sysmon

---

## Metadata

- **Author:** Elastic
- **UUID:** `b5efeb92-9b51-45b9-839f-be4cdc054ef4`
- **Integration:** `logs-endpoint.events.process-*, logs-windows.sysmon_operational-*`
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.process-*, logs-windows.sysmon_operational-*
| where @timestamp > now() - 7 day and 
  host.os.family == "windows" and event.category == "process" and event.action in ("start", "Process creation") and 
  process.parent.name.caseless == "wmiprvse.exe" and starts_with(process.code_signature.subject_name, "Microsoft")
| keep process.hash.sha256, host.id, process.name
| stats agents = count_distinct(host.id) by process.name
| where agents == 1
```

## Notes

- This hunt looks for unique process execution via Windows Management Instrumentation by removing random patterns from process.command_line and aggregating execution by count of agents with same cmdline to limit result to unique ones.
- This hunt is compatible with Sysmon, Elastic Defend and Windows Security event 4688.
## MITRE ATT&CK Techniques

- [T1047](https://attack.mitre.org/techniques/T1047)

## License

- `Elastic License v2`

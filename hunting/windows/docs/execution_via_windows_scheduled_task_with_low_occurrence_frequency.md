# Execution via Windows Scheduled Task with low occurrence frequency

---

## Metadata

- **Author:** Elastic
- **UUID:** `96d5afc8-1f25-4265-8a0e-9998091a2e1f`
- **Integration:** `logs-endpoint.events.process-*, logs-windows.sysmon_operational-*`
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.process-*, logs-windows.sysmon_operational-*
| where  @timestamp > now() - 7 day
| where host.os.family == "windows" and event.category == "process" and 
  event.action in ("start", "Process creation") and process.code_signature.trusted != true and 
  /* child process of the Tasks Schedule service */
  process.parent.name == "svchost.exe" and ends_with(process.parent.command_line, "Schedule")
| stats hosts = count_distinct(host.id) by process.hash.sha256, process.name
 /* unique hash observed in one unique agent */
| where hosts == 1
```

## Notes

- Windows security event 4688 lacks process.parent.command_line needed for this hunt to identify the Schedule svchost instance.
- Unique process.hash.sha256 and agent is not necessarily malicious, this help surface ones worth further investigation.
## MITRE ATT&CK Techniques

- [T1053](https://attack.mitre.org/techniques/T1053)
- [T1053.005](https://attack.mitre.org/techniques/T1053/005)

## License

- `Elastic License v2`

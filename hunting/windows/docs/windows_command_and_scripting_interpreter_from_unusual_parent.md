# Windows Command and Scripting Interpreter from unusual parent

---

## Metadata

- **Author:** Elastic
- **UUID:** `de929347-c04a-4a94-8be2-cbe87b25bb25`
- **Integration:** `logs-endpoint.events.process-*, logs-windows.sysmon_operational-*, logs-system.security-*`
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.process-*, logs-windows.sysmon_operational-*, logs-system.security-*
| where  @timestamp > now() - 7 day
| where host.os.family == "windows" and event.category == "process" and event.action in ("start", "Process creation", "created-process") and 
  process.name.caseless in ("cmd.exe", "powershell.exe", "conhost.exe") and 
  (starts_with(process.parent.executable.caseless, "c:\\windows\\system32") or starts_with(process.parent.executable.caseless, "c:\\windows\\syswow64"))
| keep process.name, process.parent.name, host.id
| stats hosts = count_distinct(host.id), cc = count(*) by process.parent.name
| where cc <= 10 and hosts == 1
```

## Notes

- Pivoting can be done via process.parent.name.
- Certain Microsoft binaries like lsass, winlogon,spoolsv and others should never spawn cmd.exe powershell.exe or conhost.exe, if so it's high likely malicious.
## MITRE ATT&CK Techniques

- [T1059](https://attack.mitre.org/techniques/T1059)
- [T1059.001](https://attack.mitre.org/techniques/T1059/001)
- [T1059.003](https://attack.mitre.org/techniques/T1059/003)

## License

- `Elastic License v2`

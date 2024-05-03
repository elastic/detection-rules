# Microsoft Office Child Processes with low occurrence frequency

---

## Metadata

- **Author:** Elastic
- **UUID:** `74b2e54b-7002-4201-83d6-7fd9bd5dcf0f`
- **Integration:** `logs-endpoint.events.process-*, logs-windows.sysmon_operational-*, logs-system.security-*`
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.process-*, logs-windows.sysmon_operational-*, logs-system.security-*
| where host.os.family == "windows" and @timestamp > NOW() - 15 day and 
  event.category == "process" and event.action in ("start", "Process creation", "created-process") and 
  process.parent.name.caseless in ("winword.exe", "excel.exe", "powerpnt.exe") and not starts_with(process.executable, "C:\\Program Files")
// normalize user home profile paths
| eval process_path = replace(process.executable.caseless, """[c]:\\[u][s][e][r][s]\\[a-zA-Z0-9\.\-\_\$]+\\""", "c:\\\\users\\\\user\\\\")
| stats occurrences = count(*), agents = count_distinct(agent.id) by process_path, process.parent.name 
| where occurrences == 1 and agents == 1
```

## Notes

- Certain processes like WerFault.exe, dw20.exe and dwwin.exe are often related to application crash.
- Closer attention should be attributed to lolbins and unsigned executables (Windows 4688 is not capturing process code signature information).
## MITRE ATT&CK Techniques

- [T1566](https://attack.mitre.org/techniques//T1566)

- [T1566.001](https://attack.mitre.org/techniques//T1566/001)


## License

- `Elastic License v2`

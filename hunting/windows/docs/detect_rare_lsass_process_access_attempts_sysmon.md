# Detect Rare LSASS Process Access Attempts - Sysmon

---

## Metadata

- **Author:** Elastic
- **UUID:** `3978e183-0b70-4e1c-8c40-24e367f6db5a`
- **Integration:** `logs-windows.sysmon_operational-*`
- **Language:** `ES|QL`

## Query

```sql
from logs-windows.sysmon_operational-*
| where  @timestamp > NOW() - 7 day
| where event.category == "process" and host.os.family == "windows" and event.action == "ProcessAccess" and
  winlog.event_data.TargetImage in ("C:\\Windows\\system32\\lsass.exe", "c:\\Windows\\system32\\lsass.exe", "c:\\Windows\\System32\\lsass.exe")
| keep process.executable, host.id
 /* normalize process paths to reduce known random patterns in process.executable */
| eval process_path = replace(process.executable, """([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|ns[a-z][A-Z0-9]{3,4}\.tmp|DX[A-Z0-9]{3,4}\.tmp|7z[A-Z0-9]{3,5}\.tmp|[0-9\.\-\_]{3,})""", "")
| eval process_path = replace(process_path, """[cC]:\\[uU][sS][eE][rR][sS]\\[a-zA-Z0-9\.\-\_\$~]+\\""", "C:\\\\users\\\\user\\\\")
| stats occurences = count(process_path), agents = count_distinct(host.id) by process_path
| where agents == 1 and occurences <= 10
```

## Notes

- Based on the process.executable and process.name you can pivot and investigate further the matching instances.
- Potential false positives include rare legit condition that may trigger this behavior due to third party software or Lsass crash.
## MITRE ATT&CK Techniques

- [T1003](https://attack.mitre.org/techniques//T1003)

- [T1003.001](https://attack.mitre.org/techniques//T1003/001)


## License

- `Elastic License v2`

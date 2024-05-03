# Executable File creation by an Unusual Microsoft Binary - Sysmon

---

## Metadata

- **Author:** Elastic
- **UUID:** `36c94354-9d6e-4dc5-b2aa-a7cf578a4169`
- **Integration:** `logs-windows.sysmon_operational-*`
- **Language:** `ES|QL`

## Query

```sql
from logs-windows.sysmon_operational-* 
| where  @timestamp > NOW() - 7 day 
| where host.os.family == "windows" and event.category == "file" and event.action == "FileCreate" and 
 file.extension in ("exe", "dll") and process.executable rlike """[c-fC-F]:\\Windows\\(System32|SysWOW64)\\[a-zA-Z0-9_]+.exe"""
| keep process.executable, host.id
| stats occurences = count(*), agents = count_distinct(host.id) by process.executable
| where agents == 1 and occurences <= 10
```

## Notes

- Sysmon file event don't populate file header and process code signature information thus the use of file.extension.
- Some exploits may result in the creation of an executable file by the exploited process.
- Further investigation can be done pivoting by process.executable and filter for executable file creation.
## MITRE ATT&CK Techniques

- [T1211](https://attack.mitre.org/techniques//T1211)

- [T1055](https://attack.mitre.org/techniques//T1055)


## License

- `Elastic License v2`

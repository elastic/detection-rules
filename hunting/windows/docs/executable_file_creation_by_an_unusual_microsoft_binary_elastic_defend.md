# Executable File creation by an Unusual Microsoft Binary - Elastic Defend

---

## Metadata

- **Author:** Elastic
- **UUID:** `3b2900fe-74d9-4c49-b3df-cbeceb02e841`
- **Integration:** `logs-endpoint.events.file-*`
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.file-* 
| where  @timestamp > NOW() - 7 day 
| where host.os.family == "windows" and event.category == "file" and event.action == "creation" and 
  starts_with(file.Ext.header_bytes, "4d5a") and process.code_signature.status == "trusted" and 
  starts_with(process.code_signature.subject_name, "Microsoft") and process.executable rlike """[c-fC-F]:\\Windows\\(System32|SysWOW64)\\[a-zA-Z0-9_]+.exe"""
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

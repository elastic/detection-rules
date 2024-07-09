# Executable File Creation by an Unusual Microsoft Binary

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies executable file creation by an unusual Microsoft native binary. This could be the result of
code injection or some other form of exploitation for defense evasion.

- **UUID:** `b786bcd7-b119-4ff7-b839-3927c2ff7f1f`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [windows](https://docs.elastic.co/integrations/windows)
- **Language:** `[ES|QL]`
- **Source File:** [Executable File Creation by an Unusual Microsoft Binary](../queries/executable_file_creation_by_an_unusual_microsoft_binary.toml)

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

- This hunt includes two optional queries, one for Elastic Defend data and another for Sysmon data.
- Sysmon file events don't populate file header and process code signature information thus we use `file.extension`.
- Some exploits may result in the creation of an executable file by the exploited process.
- Further investigation can be done by pivoting on `process.executable` and filtering for executable file creation.

## MITRE ATT&CK Techniques

- [T1211](https://attack.mitre.org/techniques/T1211)
- [T1055](https://attack.mitre.org/techniques/T1055)

## License

- `Elastic License v2`

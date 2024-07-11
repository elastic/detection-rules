# Persistence via Startup with Low Occurrence Frequency by Unique Host

---

## Metadata

- **Author:** Elastic
- **Description:** Leveraging frequency based analysis and path normalization, this hunt identifies rare instances where a program adds a Startup persistence via file creation. Startup entries cause programs to run each time that a user logs on and are often abused by adversaries to maintain persistence on an endpoint.
- **UUID:** `ea950361-33e4-4045-96a5-d36ca28fbc91`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [windows](https://docs.elastic.co/integrations/windows)
- **Language:** `[ES|QL]`
- **Source File:** [Persistence via Startup with Low Occurrence Frequency by Unique Host](../queries/persistence_via_startup_with_low_occurrence_frequency.toml)

## Query

```sql
from logs-endpoint.events.file-*, logs-windows.sysmon_operational-default-*
| where  @timestamp > now() - 7 day
| where host.os.family == "windows" and event.category == "file" and event.action in ("creation", "FileCreate") and
  file.path rlike """(C:\\Users\\.+\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\.+*|C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\.+)"""
| keep process.executable, host.id, file.name
 /* Paths normalization in registry.data.strings to ease aggregation */
| eval process_path = replace(process.executable, """([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|ns[a-z][A-Z0-9]{3,4}\.tmp|DX[A-Z0-9]{3,4}\.tmp|7z[A-Z0-9]{3,5}\.tmp|[0-9\.\-\_]{3,})""", "")
| eval process_path = replace(process_path, """[cC]:\\[uU][sS][eE][rR][sS]\\[a-zA-Z0-9\.\-\_\$~ ]+\\""", "C:\\\\users\\\\user\\\\")
| stats number_hosts = count_distinct(host.id) by process_path, file.name
| where number_hosts == 1
```

## Notes

- Elastic Defend file event captures the `process.code_signature` information, this can be added to the hunt to limit to unsigned and Microsoft signed programs.
- Unique `file.name` and limited to one agent is not necessarily malicious, however helps surface ones worth further investigation.
- Suspicious `process.executable` paths and LOLBins should be reviewed further.

## MITRE ATT&CK Techniques

- [T1547](https://attack.mitre.org/techniques/T1547)
- [T1547.001](https://attack.mitre.org/techniques/T1547/001)

## License

- `Elastic License v2`

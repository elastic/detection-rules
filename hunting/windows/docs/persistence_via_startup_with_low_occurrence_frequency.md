# Persistence via Startup with low occurrence frequency

---

## Metadata

- **Author:** Elastic
- **UUID:** `9d8c79fd-0006-4988-8aaa-d5f9b9a7df8e`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [windows](https://docs.elastic.co/integrations/windows)
- **Language:** `ES|QL`

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

- Elastic Defend file event captures the process.code_signature information, this can be added to the hunt to limit to unsigned and Microsoft signed programs.
- Unique file.name and limited to 1 agent is not necessarily malicious, this help surface ones worth further investigation.
- Suspicious process.executable paths and lolbins should be reviewed further.
## MITRE ATT&CK Techniques

- [T1547](https://attack.mitre.org/techniques/T1547)
- [T1547.001](https://attack.mitre.org/techniques/T1547/001)

## License

- `Elastic License v2`

# Persistence via Run Key with low occurrence frequency - Sysmon

---

## Metadata

- **Author:** Elastic
- **UUID:** `cb2d8acc-123a-4578-bd33-7004c2be9843`
- **Integration:** [windows](https://docs.elastic.co/integrations/windows)
- **Language:** `ES|QL`

## Query

```sql
from logs-windows.sysmon_operational-*
| where  @timestamp > NOW() - 7 day 
| where host.os.family == "windows" and event.category == "registry" and event.action == "RegistryEvent (Value Set)" and 
  ends_with(registry.key,"\\Microsoft\\Windows\\CurrentVersion\\Run") and 
  not registry.data.strings rlike """(.{1,2}[c-fC-F]:\\Program Files.+)|([c-fC-F]:\\Program Files.+)|(.{1,2}[c-fC-F]:\\WINDOWS\\System32\\DriverStore\\FileRepository\\.+)"""
| keep registry.key, registry.data.strings, process.name, host.id
 /* Paths normalization in registry.data.strings to ease aggregation */
| eval registry_data = replace(registry.data.strings, """([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|ns[a-z][A-Z0-9]{3,4}\.tmp|DX[A-Z0-9]{3,4}\.tmp|7z[A-Z0-9]{3,5}\.tmp|[0-9\.\-\_]{3,})""", "")
| eval registry_data = replace(registry_data, """[cC]:\\[uU][sS][eE][rR][sS]\\[a-zA-Z0-9ñ\.\-\_\$~ ]+\\""", "C:\\\\users\\\\user\\\\")
| stats cc = count(*), hosts = count_distinct(host.id) by process.name, registry_data
| where hosts == 1 and cc == 1
```

## Notes

- Sysmon registry event don't populate process code signature information (hence the separation of the queries).
- Suspicious paths and lolbins in the registry.data.strings value should be reviewed further.
## MITRE ATT&CK Techniques

- [T1547](https://attack.mitre.org/techniques/T1547)
- [T1547.001](https://attack.mitre.org/techniques/T1547/001)

## License

- `Elastic License v2`

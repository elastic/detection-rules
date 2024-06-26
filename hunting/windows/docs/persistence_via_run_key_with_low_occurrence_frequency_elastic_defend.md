# Persistence via Run Key with low occurrence frequency - Elastic Defend

---

## Metadata

- **Author:** Elastic
- **UUID:** `1078e906-0485-482e-bcf3-7ee939e07020`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.registry-*
| where  @timestamp > NOW() - 7 day 
| where host.os.family == "windows" and event.category == "registry" and event.action == "modification" and 
  (process.code_signature.exists == false or starts_with(process.code_signature.subject_name, "Microsoft")) and 
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

# CreateRemoteThread by source process with low occurrence

---

## Metadata

- **Author:** Elastic
- **UUID:** `0545f23f-84a7-4b88-9b5b-b8cfcfdc9276`
- **Integration:** [windows](https://docs.elastic.co/integrations/windows)
- **Language:** `ES|QL`

## Query

```sql
from logs-windows.sysmon_operational-* 
| where @timestamp > now() - 7 day
| where host.os.family == "windows" and event.category == "process" and event.action == "CreateRemoteThread"
| eval source_process = replace(process.executable, """[cC]:\\[uU][sS][eE][rR][sS]\\[a-zA-Z0-9ñ\.\-\_\$~ ]+\\""", "C:\\\\users\\\\user\\\\")
| stats cc = count(*), hosts = count_distinct(host.id) by source_process
 /* unique source and target processes combined and observed in 1 host */
| where hosts == 1 and cc == 1
```

## Notes

- This hunt aggregates Sysmon CreateRemoteThread events by source process and returns the ones that we observed in only one unique host. This may indicate remote process injection.
- Adding winlog.event_data.TargetImage to the group by clause can be beneficial but may introduce more legit hits.
## MITRE ATT&CK Techniques

- [T1055](https://attack.mitre.org/techniques/T1055)

## License

- `Elastic License v2`

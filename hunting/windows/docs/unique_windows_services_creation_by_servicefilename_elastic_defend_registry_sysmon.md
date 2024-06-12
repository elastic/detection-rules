# Unique Windows Services Creation by ServiceFileName - Elastic Defend Registry - Sysmon

---

## Metadata

- **Author:** Elastic
- **UUID:** `ebf79207-16dc-44f8-b10c-317d4a034bad`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [windows](https://docs.elastic.co/integrations/windows)
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.registry-*, logs-windows.sysmon_operational-* 
| where  @timestamp > now() - 7 day
| where host.os.family == "windows" and event.category == "registry" and event.action in ("modification",  "RegistryEvent (Value Set)") and 
  registry.value in ("ServiceDLL", "ImagePath") and starts_with(registry.path, "HKLM\\SYSTEM\\") and 
  process.executable != "C:\\Windows\\System32\\services.exe"
| eval process_path = replace(process.executable, """[cC]:\\[uU][sS][eE][rR][sS]\\[a-zA-Z0-9ñ\.\-\_\$~ ]+\\""", "C:\\\\users\\\\user\\\\")
| stats hosts = count_distinct(host.id), occurrences = count(*) by process_path
/* unique process.executable found in one agent */
| where hosts == 1 and occurrences == 1
```

## Notes

- This hunt identify services registry modification by unusual process based on number of hosts and occurrences history.
## MITRE ATT&CK Techniques

- [T1543](https://attack.mitre.org/techniques/T1543)
- [T1543.003](https://attack.mitre.org/techniques/T1543/003)

## License

- `Elastic License v2`

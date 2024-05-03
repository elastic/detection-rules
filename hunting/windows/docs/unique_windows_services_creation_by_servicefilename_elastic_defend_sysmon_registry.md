# Unique Windows Services Creation by ServiceFileName - Elastic Defend - Sysmon Registry

---

## Metadata

- **Author:** Elastic
- **UUID:** `688dc79d-f52a-49ad-829d-89343e68b0f7`
- **Integration:** `logs-endpoint.events.registry-*, logs-windows.sysmon_operational-*`
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.registry-*, logs-windows.sysmon_operational-* 
| where  @timestamp > now() - 7 day
| where host.os.family == "windows" and event.category == "registry" and event.action in ("modification",  "RegistryEvent (Value Set)") and 
  registry.value in ("ServiceDLL", "ImagePath") and starts_with(registry.path, "HKLM\\SYSTEM\\") and 
  not registry.data.strings rlike """(.{1,2}[c-fC-F]:\\Program Files.+)|([c-fC-F]:\\Program Files.+)|(.*\\System32\\DriverStore\\FileRepository\\.+)"""
| eval ServiceFileName = replace(registry.data.strings, """([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|ns[a-z][A-Z0-9]{3,4}\.tmp|DX[A-Z0-9]{3,4}\.tmp|7z[A-Z0-9]{3,5}\.tmp|[0-9\.\-\_]{3,})""", "")
| eval ServiceFileName = replace(ServiceFileName, """.inf_amd[a-z0-9]{5,}\\""", "_replaced_")
| eval ServiceFileName = replace(ServiceFileName, """[cC]:\\[uU][sS][eE][rR][sS]\\[a-zA-Z0-9ñ\.\-\_\$~ ]+\\""", "C:\\\\users\\\\user\\\\")
| stats cc = count(*), hosts = count_distinct(host.id) by ServiceFileName
 /* unique ServiceFileName observed in 1 host*/
| where hosts == 1 and cc == 1
```

## Notes

- This hunt aggregates created Windows services by service file name and distribution limited to unique hosts. Using the Replace command we can also further remove random pattern to reduce results to interesting events. More investigation can be conducted on instance that looks suspicious based on service file path, names and lolbins.
## MITRE ATT&CK Techniques

- [T1543](https://attack.mitre.org/techniques/T1543)
- [T1543.003](https://attack.mitre.org/techniques/T1543/003)

## License

- `Elastic License v2`

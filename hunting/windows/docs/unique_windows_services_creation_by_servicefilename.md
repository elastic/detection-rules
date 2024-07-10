# Unique Windows Services Creation by Service File Name

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt aggregates created Windows services by service file name and distribution limited to unique hosts. Using the ES|QL `Replace` command we can also further remove random patterns to reduce results to interesting events. More investigation can be conducted on instance that looks suspicious based on service file path, names and LOLBins.

- **UUID:** `48b75e53-3c73-40bd-873d-569dd8d7d925`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [windows](https://docs.elastic.co/integrations/windows), [system](https://docs.elastic.co/integrations/system)
- **Language:** `[ES|QL]`
- **Source File:** [Unique Windows Services Creation by Service File Name](../queries/unique_windows_services_creation_by_servicefilename.toml)

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

```sql
from logs-system.security-*
| where  @timestamp > now() - 7 day
| where host.os.family == "windows" and event.category == "configuration" and event.code == "4697" and
  not winlog.event_data.ServiceFileName rlike """(.{1,2}[c-fC-F]:\\Program Files.+)|([c-fC-F]:\\Program Files.+)|(.*\\System32\\DriverStore\\FileRepository\\.+)"""
| eval ServiceFileName = replace(winlog.event_data.ServiceFileName, """([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|ns[a-z][A-Z0-9]{3,4}\.tmp|DX[A-Z0-9]{3,4}\.tmp|7z[A-Z0-9]{3,5}\.tmp|[0-9\.\-\_]{3,})""", "")
| eval ServiceFileName = replace(ServiceFileName, """.inf_amd[a-z0-9]{5,}\\""", "_replaced_")
| eval ServiceFileName = replace(ServiceFileName, """[cC]:\\[uU][sS][eE][rR][sS]\\[a-zA-Z0-9ñ\.\-\_\$~ ]+\\""", "C:\\\\users\\\\user\\\\")
| stats cc = count(*), hosts = count_distinct(host.id) by ServiceFileName
| where hosts == 1 and cc == 1
```

```sql
from logs-system.system-*
| where  @timestamp > now() - 7 day
| where host.os.family == "windows" and event.code == "7045" and
  not winlog.event_data.ImagePath rlike """(.{1,2}[c-fC-F]:\\Program Files.+)|([c-fC-F]:\\Program Files.+)|(.*\\System32\\DriverStore\\FileRepository\\.+)"""
| eval ServiceFileName = replace(winlog.event_data.ImagePath, """([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|ns[a-z][A-Z0-9]{3,4}\.tmp|DX[A-Z0-9]{3,4}\.tmp|7z[A-Z0-9]{3,5}\.tmp|[0-9\.\-\_]{3,})""", "")
| eval ServiceFileName = replace(ServiceFileName, """.inf_amd[a-z0-9]{5,}\\""", "_replaced_")
| eval ServiceFileName = replace(ServiceFileName, """[cC]:\\[uU][sS][eE][rR][sS]\\[a-zA-Z0-9ñ\.\-\_\$~ ]+\\""", "C:\\\\users\\\\user\\\\")
| stats cc = count(*), hosts = count_distinct(host.id) by ServiceFileName
| where hosts == 1 and cc == 1
```

## Notes

- This hunt also identifies services registry modification by unusual process based on number of hosts and occurrences history.
- Windows event IDs 4697 and 7045 are used to identify service creation and modification.

## MITRE ATT&CK Techniques

- [T1543](https://attack.mitre.org/techniques/T1543)
- [T1543.003](https://attack.mitre.org/techniques/T1543/003)

## License

- `Elastic License v2`

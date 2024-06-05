# Unique Windows Services Creation by ServiceFileName - Windows Security 7045

---

## Metadata

- **Author:** Elastic
- **UUID:** `1749a45b-98f0-4b27-8c2f-2287230e52b7`
- **Integration:** [system](https://docs.elastic.co/integrations/system)
- **Language:** `ES|QL`

## Query

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

- This hunt aggregates created Windows services by service file name and distribution limited to unique hosts. Using the Replace command we can also further remove random pattern to reduce results to interesting events. More investigation can be conducted on instance that looks suspicious based on service file path, names and lolbins.
## MITRE ATT&CK Techniques

- [T1543](https://attack.mitre.org/techniques/T1543)
- [T1543.003](https://attack.mitre.org/techniques/T1543/003)

## License

- `Elastic License v2`

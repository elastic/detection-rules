# Low Occurrence of Drivers Loaded on Unique Hosts

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt helps identify drivers loaded once on a unique host and with a unique hash over a 15 day period of time. Advanced adversaries may leverage legit vulnerable driver to tamper with existing defences or execute code in Kernel mode.

- **UUID:** `cebfbb4d-5b2a-44d8-b763-5512b654fb26`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [windows](https://docs.elastic.co/integrations/windows), [system](https://docs.elastic.co/integrations/system)
- **Language:** `[ES|QL]`
- **Source File:** [Low Occurrence of Drivers Loaded on Unique Hosts](../queries/drivers_load_with_low_occurrence_frequency.toml)

## Query

```sql
from logs-endpoint.events.library-*
| where @timestamp > now() - 15 day
| where host.os.family == "windows" and event.category == "driver" and event.action == "load" and dll.Ext.relative_file_creation_time <= 900
| stats host_count = count_distinct(host.id), total_count = count(*), hash_count = count_distinct(dll.hash.sha256) by dll.name, dll.pe.imphash
| where host_count == 1 and total_count == 1 and hash_count == 1
```

```sql
from logs-windows.sysmon_operational-*
| where @timestamp > now() - 15 day
| where host.os.family == "windows" and event.category == "driver"
| stats host_count = count_distinct(host.id), total_count = count(*), hash_count = count_distinct(file.hash.sha256) by file.name
| where host_count == 1 and total_count == 1 and hash_count == 1
```

```sql
from logs-system.system-*
| where  @timestamp > now() - 15day
| where host.os.family == "windows" and event.code == "7045" and
  winlog.event_data.ServiceType == "kernel mode driver"
| eval ServiceFileName = replace(winlog.event_data.ImagePath, """([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|ns[a-z][A-Z0-9]{3,4}\.tmp|DX[A-Z0-9]{3,4}\.tmp|7z[A-Z0-9]{3,5}\.tmp|[0-9\.\-\_]{3,})""", "")
| eval ServiceFileName = replace(ServiceFileName, """.inf_amd[a-z0-9]{5,}\\""", "_replaced_")
| eval ServiceFileName = replace(ServiceFileName, """[cC]:\\[uU][sS][eE][rR][sS]\\[a-zA-Z0-9ñ\.\-\_\$~ ]+\\""", "C:\\\\users\\\\user\\\\")
| stats cc = count(*), hosts = count_distinct(host.id) by ServiceFileName
| where hosts == 1 and cc == 1
```

## Notes

- This hunt has three optional queries, one for Elastic Defend data, another for Sysmon data and the last one for Windows 7045 events.
- Further investigation can be done pivoting by `dll.pe.imphash` or `dll.name.`
- `dll.Ext.relative_file_creation_time` is used in the first query to limit the result to recently dropped drivers (populated in Elastic Defend).
- Aggregation can also be done by `dll.hash.sha256` / `file.hash.sha256` but will return more results.
- Bring Your Own Vulnerable Driver (BYOVD) are all signed and not malicious, further investigation should be done to check the surrounding events (service creation, process that dropped the driver etc.).

## MITRE ATT&CK Techniques

- [T1068](https://attack.mitre.org/techniques/T1068)

## License

- `Elastic License v2`

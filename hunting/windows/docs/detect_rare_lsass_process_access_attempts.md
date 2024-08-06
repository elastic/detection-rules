# Rare LSASS Process Access Attempts

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies instances where a process attempts to open the Local Security Authority Subsystem Service (LSASS) memory and where the number of occurences is limited to one unique agent and a low number of attempts. This may indicate either a rare legitimate condition or a malicious process attempting to obtain credentials or inject code into the LSASS.

- **UUID:** `d0aed6f5-f84c-4da8-bb2a-b5ca0fbb55e0`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [windows](https://docs.elastic.co/integrations/windows)
- **Language:** `[ES|QL]`
- **Source File:** [Rare LSASS Process Access Attempts](../queries/detect_rare_lsass_process_access_attempts.toml)

## Query

```sql
from logs-endpoint.events.api*
| where  @timestamp > NOW() - 7 day
| where event.category == "api" and host.os.family == "windows" and process.Ext.api.name in ("OpenProcess", "OpenThread", "ReadProcessMemory") and
 Target.process.name == "lsass.exe"
| keep process.executable.caseless, host.id
 /* normalize process paths to reduce known random patterns in process.executable */
| eval process = replace(process.executable.caseless, """([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|ns[a-z][A-Z0-9]{3,4}\.tmp|DX[A-Z0-9]{3,4}\.tmp|7z[A-Z0-9]{3,5}\.tmp|[0-9\.\-\_]{3,})""", "")
| stats occurences = count(process), agents = count_distinct(host.id) by process
| where agents == 1 and occurences <= 10
```

```sql
from logs-windows.sysmon_operational-*
| where  @timestamp > NOW() - 7 day
| where event.category == "process" and host.os.family == "windows" and event.action == "ProcessAccess" and
  winlog.event_data.TargetImage in ("C:\\Windows\\system32\\lsass.exe", "c:\\Windows\\system32\\lsass.exe", "c:\\Windows\\System32\\lsass.exe")
| keep process.executable, host.id
 /* normalize process paths to reduce known random patterns in process.executable */
| eval process_path = replace(process.executable, """([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|ns[a-z][A-Z0-9]{3,4}\.tmp|DX[A-Z0-9]{3,4}\.tmp|7z[A-Z0-9]{3,5}\.tmp|[0-9\.\-\_]{3,})""", "")
| eval process_path = replace(process_path, """[cC]:\\[uU][sS][eE][rR][sS]\\[a-zA-Z0-9\.\-\_\$~]+\\""", "C:\\\\users\\\\user\\\\")
| stats occurences = count(process_path), agents = count_distinct(host.id) by process_path
| where agents == 1 and occurences <= 10
```

## Notes

- Based on the process.executable and process.name you can pivot and investigate further for the matching instances.
- Potential false-positives include rare legitimate conditions that may trigger this behavior due to third-party software or LSASS crashing.

## MITRE ATT&CK Techniques

- [T1003](https://attack.mitre.org/techniques/T1003)
- [T1003.001](https://attack.mitre.org/techniques/T1003/001)

## License

- `Elastic License v2`

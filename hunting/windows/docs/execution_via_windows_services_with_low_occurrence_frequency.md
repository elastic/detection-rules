# Low Occurence of Process Execution via Windows Services with Unique Agent

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt looks for a low occurrence of process execution via the Windows Services Control Manager by unique agent. The Services Control Manager is responsible for starting, stopping, and interacting with system services. This could be a sign of persistence as a Windows service.

- **UUID:** `a0a84a86-115f-42f9-90a5-4cb7ceeef981`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [windows](https://docs.elastic.co/integrations/windows), [system](https://docs.elastic.co/integrations/system)
- **Language:** `[ES|QL]`
- **Source File:** [Low Occurence of Process Execution via Windows Services with Unique Agent](../queries/execution_via_windows_services_with_low_occurrence_frequency.toml)

## Query

```sql
from logs-endpoint.events.process-*, logs-windows.sysmon_operational-*
| where  @timestamp > now() - 7 day
| where host.os.family == "windows" and event.category == "process" and event.action in ("start", "Process creation") and
  process.parent.name == "services.exe" and process.code_signature.trusted != true
| stats hosts = count_distinct(host.id) by process.hash.sha256, process.name
 /* unique hash observed in one unique agent */
| where hosts == 1
```

```sql
from logs-system.security-*
| where  @timestamp > now() - 7 day
| where host.os.family == "windows" and event.category == "process" and event.code == "4688" and
  event.action == "created-process" and process.parent.name == "services.exe"
| eval process_path = replace(process.executable, """([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|ns[a-z][A-Z0-9]{3,4}\.tmp|DX[A-Z0-9]{3,4}\.tmp|7z[A-Z0-9]{3,5}\.tmp|[0-9\.\-\_]{3,})""", "")
| eval process_path = replace(process_path, """[cC]:\\[uU][sS][eE][rR][sS]\\[a-zA-Z0-9\.\-\_\$~]+\\""", "C:\\\\users\\\\user\\\\")
| stats hosts = count_distinct(host.id) by process_path
 /* unique path observed in one unique agent */
| where hosts == 1
```

## Notes

- This hunt contains two queries for Elastic Defend and Windows Security event 4688.
- Windows security event 4688 lacks code signature and hash information, hence the use of `process.executable` for aggregation.
- Unique `process.hash.sha256` and agent is not necessarily malicious, this help surface ones worth further investigation.
- Suspicious `process.executable` paths and LOLBins should be reviewed further.

## MITRE ATT&CK Techniques

- [T1543](https://attack.mitre.org/techniques/T1543)
- [T1543.003](https://attack.mitre.org/techniques/T1543/003)

## License

- `Elastic License v2`

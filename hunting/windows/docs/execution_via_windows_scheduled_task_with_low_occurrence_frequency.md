# Low Frequency of Process Execution via Windows Scheduled Task by Unique Agent

---

## Metadata

- **Author:** Elastic
- **Description:** Aggregating by paths/hash, this hunt identifies rare instances where a program executes as a child process of the Tasks Scheduler service. This could be the result of persistence as a Windows Scheduled Task.

- **UUID:** `0d960760-8a40-49c1-bbdd-4deb32c7fd67`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [windows](https://docs.elastic.co/integrations/windows)
- **Language:** `[ES|QL]`
- **Source File:** [Low Frequency of Process Execution via Windows Scheduled Task by Unique Agent](../queries/execution_via_windows_scheduled_task_with_low_occurrence_frequency.toml)

## Query

```sql
from logs-endpoint.events.process-*, logs-windows.sysmon_operational-*
| where  @timestamp > now(-) - 7 day
| where host.os.family == "windows" and event.category == "process" and
  event.action in ("start", "Process creation") and process.code_signature.trusted != true and
  /* child process of the Tasks Schedule service */
  process.parent.name == "svchost.exe" and ends_with(process.parent.command_line, "Schedule")
| stats hosts = count_distinct(host.id) by process.hash.sha256, process.name
 /* unique hash observed in one unique agent */
| where hosts == 1
```

## Notes

- Windows security event 4688 lacks `process.parent.command_line` needed for this hunt to identify the Schedule `svchost` instance.
- Unique `process.hash.sha256` and agent is not necessarily malicious, however this helps surface signals worth further investigation.

## MITRE ATT&CK Techniques

- [T1053](https://attack.mitre.org/techniques/T1053)
- [T1053.005](https://attack.mitre.org/techniques/T1053/005)

## License

- `Elastic License v2`

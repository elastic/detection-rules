# Windows Command and Scripting Interpreter from Unusual Parent Process

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt looks for unusual Microsoft native processes spawning `cmd.exe`, `powershell.exe` or `conhost.exe` and limited to a unique host. This could be normal rare behavior as well as an interactive shell activity from an injected parent process to execute system commands.

- **UUID:** `aca4877f-d284-4bdb-8e18-b1414d3a7c20`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [windows](https://docs.elastic.co/integrations/windows), [system](https://docs.elastic.co/integrations/system)
- **Language:** `[ES|QL]`
- **Source File:** [Windows Command and Scripting Interpreter from Unusual Parent Process](../queries/windows_command_and_scripting_interpreter_from_unusual_parent.toml)

## Query

```sql
from logs-endpoint.events.process-*, logs-windows.sysmon_operational-*, logs-system.security-*
| where  @timestamp > now() - 7 day
| where host.os.family == "windows" and event.category == "process" and event.action in ("start", "Process creation", "created-process") and
  to_lower(process.name) in ("cmd.exe", "powershell.exe", "conhost.exe") and
  (starts_with(to_lower(process.parent.executable), "c:\\windows\\system32") or starts_with(to_lower(process.parent.executable), "c:\\windows\\syswow64"))
| keep process.name, process.parent.name, host.id
| stats hosts = count_distinct(host.id), cc = count(*) by process.parent.name
| where cc <= 10 and hosts == 1
```

## Notes

- Further pivoting can be done via `process.parent.name`.
- Certain Microsoft binaries like LSASS, winlogon, spoolsv and others should never spawn `cmd.exe`, `powershell.exe` or `conhost.exe`, if so it's highly likely malicious.

## MITRE ATT&CK Techniques

- [T1059](https://attack.mitre.org/techniques/T1059)
- [T1059.001](https://attack.mitre.org/techniques/T1059/001)
- [T1059.003](https://attack.mitre.org/techniques/T1059/003)

## License

- `Elastic License v2`

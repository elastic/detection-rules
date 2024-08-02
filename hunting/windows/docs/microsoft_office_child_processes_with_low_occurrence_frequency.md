# Microsoft Office Child Processes with Low Occurrence Frequency by Unique Agent

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt looks for Microsoft Office child processes with low occurrence frequency. This could be a normal rare behavior as well as potential execution via a malicious document. Adversaries may use Microsoft Office applications to execute malicious code, such as macros, scripts, or other payloads.

- **UUID:** `f1b8519a-4dae-475f-965a-f53559233eab`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [windows](https://docs.elastic.co/integrations/windows), [system](https://docs.elastic.co/integrations/system)
- **Language:** `[ES|QL]`
- **Source File:** [Microsoft Office Child Processes with Low Occurrence Frequency by Unique Agent](../queries/microsoft_office_child_processes_with_low_occurrence_frequency.toml)

## Query

```sql
from logs-endpoint.events.process-*, logs-windows.sysmon_operational-*, logs-system.security-*
| where host.os.family == "windows" and @timestamp > NOW() - 15 day and
  event.category == "process" and event.action in ("start", "Process creation", "created-process") and
  to_lower(process.parent.name) in ("winword.exe", "excel.exe", "powerpnt.exe") and not starts_with(process.executable, "C:\\Program Files")
// normalize user home profile paths
| eval process_path = replace(to_lower(process.executable), """[c]:\\[u][s][e][r][s]\\[a-zA-Z0-9\.\-\_\$]+\\""", "c:\\\\users\\\\user\\\\")
| stats occurrences = count(*), agents = count_distinct(agent.id) by process_path, process.parent.name
| where occurrences == 1 and agents == 1
```

## Notes

- Certain processes like `WerFault.exe`, `dw20.exe` and `dwwin.exe` are often related to application crash.
- Closer attention should be attributed to lolbins and unsigned executables (Windows 4688 is not capturing process code signature information).

## MITRE ATT&CK Techniques

- [T1566](https://attack.mitre.org/techniques/T1566)
- [T1566.001](https://attack.mitre.org/techniques/T1566/001)

## License

- `Elastic License v2`

# Startup Execution with Low Occurrence Frequency by Unique Host

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies programs started shortly after user logon and presence limited to a unique host. Run registry key and Startup folder cause programs to run each time that a user logs on and are often abused by malwares to maintain persistence on an endpoint.

- **UUID:** `52a958e8-0368-4e74-bd4b-a64faf397bf4`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL]`
- **Source File:** [Startup Execution with Low Occurrence Frequency by Unique Host](../queries/execution_via_startup_with_low_occurrence_frequency.toml)

## Query

```sql
from logs-endpoint.events.process-*
| where host.os.family == "windows" and event.category == "process" and event.action == "start" and
  /* programs started shortly after user logon like startup items */
  process.parent.executable.caseless == "c:\\windows\\explorer.exe" and process.Ext.session_info.relative_logon_time <= 100 and
  not starts_with(process.executable, "C:\\Program Files") and not starts_with(process.executable, "C:\\Windows\\System32\\DriverStore\\FileRepository\\") and
  /* this hunt is scoped to unsigned or untrusted code-sig or Microsoft signed binaries to not miss lolbins */
  (process.code_signature.exists == false or process.code_signature.trusted == false or starts_with(process.code_signature.subject_name, "Microsoft"))
| keep process.executable, host.id, process.hash.sha256
| eval process_path = replace(process.executable, """([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|ns[a-z][A-Z0-9]{3,4}\.tmp|DX[A-Z0-9]{3,4}\.tmp|7z[A-Z0-9]{3,5}\.tmp|[0-9\.\-\_]{3,})""", "")
| eval process_path = replace(process_path, """[cC]:\\[uU][sS][eE][rR][sS]\\[a-zA-Z0-9\.\-\_\$~' ]+\\""", "C:\\\\users\\\\user\\\\")
| stats hosts = count_distinct(host.id) by process_path, process.hash.sha256
| where hosts == 1
```

## Notes

- Items set to persist via Startup such as Run keys and Startup folder will be executed by `Explorer.exe` shortly after user logon (`process.Ext.session_info.relative_logon_time` helps us to capture that time difference).
- Special attention to unknown hashes, suspicious paths and LOLBins should be given.

## MITRE ATT&CK Techniques

- [T1547](https://attack.mitre.org/techniques/T1547)
- [T1547.001](https://attack.mitre.org/techniques/T1547/001)

## License

- `Elastic License v2`

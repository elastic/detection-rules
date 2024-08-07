# DLL Hijack via Masquerading as Microsoft Native Libraries

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies when a process loads a DLL normally located in `System32` or `SysWOW64` folders from an unusual path. Adversaries may execute their own malicious payloads by side-loading malicious DLLs. The host count also should help exclude false-positives by looking at low occurrences when this abnormal behavior is limited to unique agents.
- **UUID:** `d06bc067-6174-412f-b1c9-bf8f15149519`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [windows](https://docs.elastic.co/integrations/windows)
- **Language:** `[ES|QL]`
- **Source File:** [DLL Hijack via Masquerading as Microsoft Native Libraries](../queries/detect_dll_hijack_via_masquerading_as_microsoft_native_libraries.toml)

## Query

```sql
from logs-endpoint.events.library-*
| where @timestamp > NOW() - 7 day
| where host.os.family == "windows" and event.action == "load" and process.code_signature.status == "trusted" and dll.code_signature.status != "trusted" and
 not dll.path rlike """[c-fC-F]:\\(Windows|windows|WINDOWS)\\(System32|SysWOW64|system32|syswow64)\\[a-zA-Z0-9_]+.dll"""
| keep dll.name, dll.path, dll.hash.sha256, process.executable, host.id
 /* steps how to create DL enrichment policy https://gist.github.com/Samirbous/9f9c3237a0ada745e71cc2ba3425311c  */
| ENRICH libs-policy-defend
 /* if the DLL is normally located is system32 or syswow64 folders, native tag will be equal to yes */
| where native == "yes" and not starts_with(dll.path, "C:\\Windows\\assembly\\NativeImages")
 /* normalize paths by removing random patterns */
| eval process_path = replace(process.executable, """([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|ns[a-z][A-Z0-9]{3,4}\.tmp|DX[A-Z0-9]{3,4}\.tmp|7z[A-Z0-9]{3,5}\.tmp|[0-9\.\-\_]{3,})""", ""),
  dll_path = replace(dll.path, """([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|ns[a-z][A-Z0-9]{3,4}\.tmp|DX[A-Z0-9]{3,4}\.tmp|7z[A-Z0-9]{3,5}\.tmp|[0-9\.\-\_]{3,})""", "")
| stats host_count = count_distinct(host.id) by dll.name, dll_path, process_path, dll.hash.sha256
| sort host_count asc
```

```sql
from logs-windows.sysmon_operational-*
| where @timestamp > NOW() - 7 day
| where host.os.family == "windows" and  event.category == "process" and event.action == "Image loaded" and file.code_signature.status != "Valid" and
 not file.path rlike """[c-fC-F]:\\(Windows|windows|WINDOWS)\\(System32|SysWOW64|system32|syswow64)\\[a-zA-Z0-9_]+.dll"""
| keep file.name, file.path, file.hash.sha256, process.executable, host.id
 /* steps to create DL enrichment policy https://gist.github.com/Samirbous/9f9c3237a0ada745e71cc2ba3425311c - just replace dll by file */
| ENRICH libs-policy-sysmon
 /* if the DLL is normally located is system32 or syswow64 folders, native tag will be equal to yes */
| where native == "yes" and not starts_with(file.path, "C:\\Windows\\assembly\\NativeImages")
 /* normalize paths by removing random patterns */
| eval process_path = replace(process.executable, """([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|ns[a-z][A-Z0-9]{3,4}\.tmp|DX[A-Z0-9]{3,4}\.tmp|7z[A-Z0-9]{3,5}\.tmp|[0-9\.\-\_]{3,})""", ""),
  dll_path = replace(file.path, """([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|ns[a-z][A-Z0-9]{3,4}\.tmp|DX[A-Z0-9]{3,4}\.tmp|7z[A-Z0-9]{3,5}\.tmp|[0-9\.\-\_]{3,})""", "")
| stats host_count = count_distinct(host.id) by file.name, dll_path, process_path, file.hash.sha256
| sort host_count asc
```

## Notes

- This hunt has two optional queries, one for Elastic Defend data and another for Sysmon data.
- This hunt requires the creation of an [enrichment policy](https://www.elastic.co/guide/en/elasticsearch/reference/current/esql-enrich-data.html) to use with the ES|QL (ENRICH command).
- The `dll.hash.sha256` field can be used to pivot and further investigate the DLL origin and purpose.
- Paths like `C:\Users\Public and C:\ProgramData\` are often observed in malware employing DLL side-loading.

## MITRE ATT&CK Techniques

- [T1574](https://attack.mitre.org/techniques/T1574)
- [T1574.001](https://attack.mitre.org/techniques/T1574/001)

## License

- `Elastic License v2`

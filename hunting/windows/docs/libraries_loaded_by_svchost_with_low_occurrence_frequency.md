# Libraries Loaded by svchost with Low Occurrence Frequency

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt returns the SHA256 hash and the `dll.path` of unsigned libraries loaded by svchost where the presence of unique path/hash is limited to a unique host. Adversaries may use Windows service DLLs to maintain persistence or run with System privileges.

- **UUID:** `c00f1afe-4f25-4542-8cc9-277b23581121`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [windows](https://docs.elastic.co/integrations/windows)
- **Language:** `[ES|QL]`
- **Source File:** [Libraries Loaded by svchost with Low Occurrence Frequency](../queries/libraries_loaded_by_svchost_with_low_occurrence_frequency.toml)

## Query

```sql
from logs-endpoint.events.library-*
| where @timestamp > NOW() - 7 day
| where host.os.family == "windows" and event.category == "library" and event.action == "load" and
  process.name == "svchost.exe" and (dll.code_signature.trusted == false or dll.code_signature.exists == false) and dll.hash.sha256 like "?*" and
  (dll.Ext.relative_file_creation_time <= 900 or dll.Ext.relative_file_name_modify_time <= 900)
| keep dll.name, dll.path, dll.hash.sha256, host.id
| eval dll_folder = substring(dll.path, 1, length(dll.path) - (length(dll.name) + 1))
 /* paths normalization by removing random patterns */
| eval dll_path = replace(dll_folder, """([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|ns[a-z][A-Z0-9]{3,4}\.tmp|DX[A-Z0-9]{3,4}\.tmp|7z[A-Z0-9]{3,5}\.tmp|[0-9\.\-\_]{3,})""", "replaced")
| eval dll_path = replace(dll_path, """[cC]:\\[uU][sS][eE][rR][sS]\\[a-zA-Z0-9\.\-\_\$~]+\\""", "C:\\\\users\\\\user\\\\")
| eval dll_path = replace(dll_path, """SoftwareDistribution\\Download\\[a-z0-9]+""", """SoftwareDistribution\\Download\\""")
| stats hosts = count_distinct(host.id), count_dlls_per_folder = count(dll_path) by dll_path, dll.name, dll.hash.sha256
| where hosts == 1 and count_dlls_per_folder == 1
```

```sql
from logs-windows.sysmon_operational-*
| where @timestamp > NOW() - 7 day
| where host.os.family == "windows" and event.category == "process" and event.action == "Image loaded" and
  process.name == "svchost.exe" and file.code_signature.status != "Valid" and file.hash.sha256 like "?*"
| keep file.name, file.path, file.hash.sha256, host.id
| eval dll_folder = substring(file.path, 1, length(file.path) - (length(file.name) + 1))
/* paths normalization by removing random patterns */
| eval dll_path = replace(dll_folder, """([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|ns[a-z][A-Z0-9]{3,4}\.tmp|DX[A-Z0-9]{3,4}\.tmp|7z[A-Z0-9]{3,5}\.tmp|[0-9\.\-\_]{3,})""", "replaced")
| eval dll_path = replace(dll_path, """[cC]:\\[uU][sS][eE][rR][sS]\\[a-zA-Z0-9\.\-\_\$~]+\\""", "C:\\\\users\\\\user\\\\")
| eval dll_path = replace(dll_path, """SoftwareDistribution\\Download\\[a-z0-9]+""", """SoftwareDistribution\\Download\\""")
| stats hosts = count_distinct(host.id), count_dlls_per_folder = count(dll_path) by dll_path, file.name, file.hash.sha256
| where hosts == 1 and count_dlls_per_folder == 1
```

## Notes

- This hunt includes two queries to cover both Sysmon and Elastic Defend data sources.
- The hunt uses Elastic Defend library events for an extra optional condition `dll.Ext.relative_file_creation_time` to scope if for recently dropped DLLs.
- The `count_dlls_per_folder` variable filter is used to avoid cases where multiple DLLs with different names are loaded from same directory (often observed in FPs loaded multiple dependencies from same dir).
- Pay close attention unknown hashes and suspicious paths, usually ServiceDLLs are located in trusted directories like `%programfiles%` and `system32/syswow64`.

## MITRE ATT&CK Techniques

- [T1543](https://attack.mitre.org/techniques/T1543)
- [T1543.003](https://attack.mitre.org/techniques/T1543/003)

## License

- `Elastic License v2`

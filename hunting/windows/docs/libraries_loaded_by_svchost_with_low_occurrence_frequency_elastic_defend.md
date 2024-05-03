# Libraries loaded by svchost with low occurrence frequency - Elastic Defend

---

## Metadata

- **Author:** Elastic
- **UUID:** `e37fe0b9-1b70-4800-8989-58bac5a0a9bb`
- **Integration:** `logs-endpoint.events.library-*`
- **Language:** `ES|QL`

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

## Notes

- The hunt using Elastic Defend library events uses an extra optional condition dll.Ext.relative_file_creation_time to scope if for recently dropped DLLs.
- The count_dlls_per_folder variable filter is used to avoid cases where multiple DLLs with different names are loaded from same directory (often observed in FPs loaded multiple dependencies from same dir).
- Pay close attention unknown hashes and suspicious paths, usually ServiceDLLs are located in trusted directories like %programfiles% and system32/syswow64.
## MITRE ATT&CK Techniques

- [T1543](https://attack.mitre.org/techniques//T1543)

- [T1543.003](https://attack.mitre.org/techniques//T1543/003)


## License

- `Elastic License v2`

# Detect DLL Hijack via Masquerading as Microsoft Native Libraries - Elastic Defend

---

## Metadata

- **Author:** Elastic
- **UUID:** `87c97865-fdaa-48b2-bfa6-67bed7cf56ef`
- **Integration:** `logs-endpoint.events.library-*`
- **Language:** `ES|QL`

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

## Notes

- This hunt require the creation of an enrichment policy to use with the ES|QL (ENRICH command).
- Using dll.hash.sha256 for Elastic Defend or file.hash.sha256 for Sysmon you can pivot to further investigate the DLL origin and purpose.
- Paths like C:\Users\Public and C:\ProgramData\ are often observed in malware employing DLL side-loading.
- Process code signature information is not captured in Sysmon Image Load Events (not present in the ES|QL hunt).
## MITRE ATT&CK Techniques

- [T1574](https://attack.mitre.org/techniques/T1574)
- [T1574.001](https://attack.mitre.org/techniques/T1574/001)

## License

- `Elastic License v2`

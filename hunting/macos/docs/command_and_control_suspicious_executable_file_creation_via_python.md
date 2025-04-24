# Suspcious Executable File Creation via Python

---

## Metadata

- **Author:** Elastic
- **Description:** Detects suspicious creation of executable files by Python processes in commonly abused directories 
on macOS systems. These locations, such as /Users/Shared, /tmp, or /private/tmp, are frequently used by adversaries 
and post-exploitation frameworks to stage or drop payloads. The detection leverages the ELF or Mach-O magic bytes 
to confirm executables are written to disk.

- **UUID:** `9aaf1113-cf7a-4fd7-b796-f6456fdaffb5`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[EQL]`
- **Source File:** [Suspcious Executable File Creation via Python](../queries/command_and_control_suspicious_executable_file_creation_via_python.toml)

## Query

```sql
file where event.action == "modification" and
  process.name like~ "python*" and
  file.Ext.header_bytes like~ ("cffaedfe*", "cafebabe*") and
  file.path like ("/Users/Shared/*", "/tmp/*", "/private/tmp/*", "/Users/*/Public/*") and
  not file.extension in ("dylib", "so")
```

## Notes

- Creation or modification of executable binaries in these directories is odd and rare in normal operations.
- This hunt is useful for detecting dropper-style behavior during post-exploitation or initial access.

## MITRE ATT&CK Techniques

- [T1059.006](https://attack.mitre.org/techniques/T1059/006)
- [T1105](https://attack.mitre.org/techniques/T1105)

## References

- https://www.elastic.co/security-labs/dprk-code-of-conduct
- https://unit42.paloaltonetworks.com/slow-pisces-new-custom-malware/
- https://slowmist.medium.com/cryptocurrency-apt-intelligence-unveiling-lazarus-groups-intrusion-techniques-a1a6efda7d34
- https://x.com/safe/status/1897663514975649938
- https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/

## License

- `Elastic License v2`

# Python Library Load and Delete

---

## Metadata

- **Author:** Elastic
- **Description:** Detects when a Python process loads a library from a user's home directory and then deletes that library within a short time window. This may indicate an attempt to execute malicious code in memory and remove evidence from disk as a form of defense evasion.

- **UUID:** `76a1f901-4495-4cbd-a35a-7ff8d116602b`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[EQL]`
- **Source File:** [Python Library Load and Delete](../queries/defense_evasion_python_library_load_and_delete.toml)

## Query

```sql
sequence by process.entity_id with maxspan=15s
  [library where event.action == "load" and dll.path like "/Users/*" and process.name like~ "python"]
  [file where event.action == "deletion" and startswith~(file.path, dll.path)]
```

## Notes

- This hunting rule helps identify potential in-memory execution or anti-forensic behavior by Python-based malware.
- Library load followed by quick deletion is suspicious, especially in user directories.
- Consider pivoting on `process.entity_id` to examine surrounding process activity and file writes.

## MITRE ATT&CK Techniques

- [T1059.006](https://attack.mitre.org/techniques/T1059/006)
- [T1070.004](https://attack.mitre.org/techniques/T1070/004)

## References

- https://www.elastic.co/security-labs/dprk-code-of-conduct
- https://unit42.paloaltonetworks.com/slow-pisces-new-custom-malware/
- https://slowmist.medium.com/cryptocurrency-apt-intelligence-unveiling-lazarus-groups-intrusion-techniques-a1a6efda7d34
- https://x.com/safe/status/1897663514975649938
- https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/

## License

- `Elastic License v2`

# Self-Deleted Python Script Accessing Sensitive Files

---

## Metadata

- **Author:** Elastic
- **Description:** Detects access to potentially sensitive files by a Python script that deletes itself from disk. This behavior is characteristic of sophisticated malware that executes from memory and avoids leaving behind forensic artifacts. Notably used in high-profile DPRK-linked financial heists.

- **UUID:** `7ab00c3d-0ed3-4e4b-9806-b19959bf6b12`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[EQL]`
- **Source File:** [Self-Deleted Python Script Accessing Sensitive Files](../queries/defense_evasion_self_deleted_python_script_accessing_sensitive_files.toml)

## Query

```sql
sequence by process.entity_id with maxspan=15s
  [file where event.action == "deletion" and file.extension in ("py", "pyc") and process.name like~ "python*"]
  [file where event.action == "open"]
```

## Notes

- This hunt detects Python-based scripts that self-delete and continue to access sensitive files (e.g., AWS credentials, SSH keys, keychains).
- File paths in this logic can be enriched or customized to detect access to specific secrets in your environment.
- Ideal for detecting evasive memory-resident malware and credential theft operations.

## MITRE ATT&CK Techniques

- [T1059.006](https://attack.mitre.org/techniques/T1059/006)
- [T1070.004](https://attack.mitre.org/techniques/T1070/004)
- [T1552.001](https://attack.mitre.org/techniques/T1552/001)

## References

- https://www.elastic.co/security-labs/dprk-code-of-conduct
- https://unit42.paloaltonetworks.com/slow-pisces-new-custom-malware/
- https://slowmist.medium.com/cryptocurrency-apt-intelligence-unveiling-lazarus-groups-intrusion-techniques-a1a6efda7d34
- https://x.com/safe/status/1897663514975649938
- https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/

## License

- `Elastic License v2`

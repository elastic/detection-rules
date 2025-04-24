# Unusual Library Load via Python

---

## Metadata

- **Author:** Elastic
- **Description:** Detects when a library is loaded from a user's home directory by a Python process and the loaded file is not a typical shared object (.so) or dynamic library (.dylib). This may indicate side-loading of malicious or non-standard files in script-based execution environments.

- **UUID:** `d9b30b84-dc53-413c-a7e4-f42078b10048`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[EQL]`
- **Source File:** [Unusual Library Load via Python](../queries/execution_unusual_library_load_via_python.toml)

## Query

```sql
library where event.action == "load" and
  dll.path like "/Users/*" and
  process.name like~ "python*" and
  not dll.name : ("*.so", "*.dylib")
```

## Notes

- Loading libraries from /Users is rare and may suggest untrusted or attacker-deployed components.
- This hunt helps uncover suspicious Python-driven library loads that bypass traditional extension-based detection.
- Consider tuning to exclude known development or research environments that store legitimate libraries in home directories.

## MITRE ATT&CK Techniques

- [T1059.006](https://attack.mitre.org/techniques/T1059/006)

## References

- https://www.elastic.co/security-labs/dprk-code-of-conduct
- https://unit42.paloaltonetworks.com/slow-pisces-new-custom-malware/
- https://slowmist.medium.com/cryptocurrency-apt-intelligence-unveiling-lazarus-groups-intrusion-techniques-a1a6efda7d34
- https://x.com/safe/status/1897663514975649938
- https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/

## License

- `Elastic License v2`

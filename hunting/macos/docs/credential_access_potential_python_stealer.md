# Potential Python Stealer Activity

---

## Metadata

- **Author:** Elastic
- **Description:** Detects the execution of a Python script followed by at least three consecutive open actions on files within a 30-second window. This behavior may indicate an attempt to access or exfiltrate sensitive data such as browser files, credentials, or configuration files.

- **UUID:** `107fe9a2-6743-4136-a055-fa070fd38f2f`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[EQL]`
- **Source File:** [Potential Python Stealer Activity](../queries/credential_access_potential_python_stealer.toml)

## Query

```sql
sequence by process.entity_id with maxspan=30s
  [process where event.type == "start" and event.action == "exec" and
    process.name like~ "python*" and process.args_count == 2 and
    process.args like ("/Users/*", "/tmp/*", "/private/tmp/*")]
  [file where event.action == "open"]
  [file where event.action == "open"]
  [file where event.action == "open"]
```

## Notes

- This hunt identifies Python-based access to multiple files shortly after script execution, a pattern common to stealers.
- Adjustments may be needed to focus on high-value file paths (e.g., browser data, tokens, configuration files).
- Further pivoting on `file.path`, `process.entity_id`, and `process.args` is recommended for triage.

## MITRE ATT&CK Techniques

- [T1059.006](https://attack.mitre.org/techniques/T1059/006)
- [T1552.001](https://attack.mitre.org/techniques/T1552/001)

## References

- https://www.elastic.co/security-labs/dprk-code-of-conduct
- https://unit42.paloaltonetworks.com/slow-pisces-new-custom-malware/
- https://slowmist.medium.com/cryptocurrency-apt-intelligence-unveiling-lazarus-groups-intrusion-techniques-a1a6efda7d34
- https://x.com/safe/status/1897663514975649938
- https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/

## License

- `Elastic License v2`

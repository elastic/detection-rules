# Unsigned or Untrusted Binary Execution via Python

---

## Metadata

- **Author:** Elastic
- **Description:** Detects the execution of unsigned or untrusted binaries where the parent process is a Python interpreter. Adversaries often use Python as a launcher to run untrusted payloads, typically dropped to locations like `/tmp`, `/Users/Shared`, or public directories. This behavior is indicative of custom loaders, malware staging, or post-exploitation actions.

- **UUID:** `9aaf1113-cf7a-4fd7-b796-f6456fdaffb5`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[EQL]`
- **Source File:** [Unsigned or Untrusted Binary Execution via Python](../queries/execution_unsigned_or_untrusted_binary_execution_via_python.toml)

## Query

```sql
process where event.type == "start" and event.action == "exec" and
  (process.code_signature.trusted == false or process.code_signature.exists == false) and
  process.parent.name like~ "python*" and
  (
    process.executable like "/Users/Shared/*" or
    process.executable like "/tmp/*" or
    process.executable like "/private/tmp/*" or
    process.executable like "/Users/*/Public/*" or
    process.name like ".*"
  )
```

## Notes

- Execution of untrusted binaries from Python in shared or temporary directories is rare in normal operations.
- This hunt is useful for detecting dropper-style behavior during post-exploitation or initial access.
- You may wish to enrich with file.hash or process.args to gain more triage context.

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

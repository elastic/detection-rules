# Python Script Drop and Execute

---

## Metadata

- **Author:** Elastic
- **Description:** Detects when a Python script is written to disk within a user's home directory and then immediately executed by the same process lineage. This pattern is commonly observed in initial access payload delivery or script-based malware staging.

- **UUID:** `76f10746-9527-4c99-8ed8-491085ecdcfd`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[EQL]`
- **Source File:** [Python Script Drop and Execute](../queries/execution_python_script_drop_and_execute.toml)

## Query

```sql
sequence with maxspan=15s
  [file where event.action == "modification" and process.name like~ "python*" and
   file.extension == "py" and file.path like "/Users/*"] by process.entity_id
  [process where event.type == "start" and event.action == "exec" and
   process.args_count == 2 and process.args like "/Users/*"] by process.parent.entity_id
```

## Notes

- This hunt is designed to catch malicious tooling written and executed rapidly by Python processes.
- This technique is often used by downloaders or droppers that write staging scripts and immediately run them.
- Consider pivoting on `process.entity_id` and `file.path` to view subsequent behavior.

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

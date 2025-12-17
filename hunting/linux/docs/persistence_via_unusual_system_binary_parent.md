# Unusual System Binary Parent (Potential System Binary Hijacking Attempt)

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies potential system binary hijacking attempts on Linux systems. It monitors process execution events where common system binaries such as ls, cat, mkdir, touch, mv, and cp are the parent processes. These activities can indicate attempts to hijack system binaries for malicious purposes. The hunt lists detailed information for further analysis and investigation.

- **UUID:** `d22cbe8f-c84d-4811-aa6d-f1ee00c806b2`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL]`
- **Source File:** [Unusual System Binary Parent (Potential System Binary Hijacking Attempt)](../queries/persistence_via_unusual_system_binary_parent.toml)

## Query

```sql
from logs-endpoint.events.process-*
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.action == "exec" and event.type == "start" and process.parent.name in ("ls", "cat", "mkdir", "touch", "mv", "cp")
| stats cc = count(), host_count = count_distinct(host.name) by process.parent.executable, process.executable
| where host_count <= 5
| sort cc asc
| limit 100
```

## Notes

- Monitors process execution events where common system binaries such as ls, cat, mkdir, touch, mv, and cp are the parent processes.
- Focuses on identifying unusual or suspicious child processes spawned by these common system binaries.
- Uses stats to count occurrences and identify unusual activity by looking at the number of unique hosts and processes involved.
- Requires additional data analysis and investigation into results to identify malicious or unauthorized use of system binaries.

## MITRE ATT&CK Techniques

- [T1546.004](https://attack.mitre.org/techniques/T1546/004)
- [T1059.004](https://attack.mitre.org/techniques/T1059/004)

## License

- `Elastic License v2`

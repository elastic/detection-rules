# Defense Evasion via Capitalized Process Execution

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies potential defense evasion techniques via capitalized process execution on Linux systems. It detects processes that have two or more consecutive capital letters within their names, which can indicate an attempt to evade detection. Such naming conventions are often used in malicious payloads to blend in with legitimate processes.

- **UUID:** `9d485892-1ca2-464b-9e4e-6b21ab379b9a`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL]`
- **Source File:** [Defense Evasion via Capitalized Process Execution](../queries/defense_evasion_via_capitalized_process_execution.toml)

## Query

```sql
from logs-endpoint.events.process-*
| where @timestamp > now() - 10 day
| where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  (process.name rlike """[A-Z]{2,}[a-z]{1,}[0-9]{0,}""") or
  (process.name rlike """[A-Z]{1,}[0-9]{0,}""")
)
| stats cc = count(), host_count = count_distinct(host.name) by process.name
// Alter this threshold to make sense for your environment
| where cc <= 3 and host_count <= 3
| limit 100
```

## Notes

- Detects processes that have two or more consecutive capital letters within their names, with optional digits.
- This technique is often used in malicious payloads, such as Metasploit payloads, to evade detection.
- Included a process count of <= 3 and a host count of <= 3 to eliminate common processes across different hosts.

## MITRE ATT&CK Techniques

- [T1036.004](https://attack.mitre.org/techniques/T1036/004)
- [T1070](https://attack.mitre.org/techniques/T1070)

## License

- `Elastic License v2`

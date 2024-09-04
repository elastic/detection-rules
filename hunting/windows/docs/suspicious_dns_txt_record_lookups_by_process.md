# Suspicious DNS TXT Record Lookups by Process

---

## Metadata

- **Author:** Elastic
- **Description:** Leveraging aggregation by process executable entities, this hunt identifies identifies a high number of DNS TXT record queries from same process.
Adversaries may leverage DNS TXT queries to stage malicious content or exfiltrate data.

- **UUID:** `7a2c8397-d219-47ad-a8e2-93562e568d08`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [windows](https://docs.elastic.co/integrations/windows)
- **Language:** `[ES|QL]`
- **Source File:** [Suspicious DNS TXT Record Lookups by Process](../queries/suspicious_dns_txt_record_lookups_by_process.toml)

## Query

```sql
from logs-endpoint.events.network-*, logs-windows.sysmon_operational-*
| where host.os.family == "windows" and event.category == "network" and
  event.action in ("lookup_requested", "DNSEvent (DNS query)") and
  (dns.question.type == "TXT" or dns.answers.type == "TXT") and process.executable != "C:\\Windows\\system32\\svchost.exe"
| keep process.executable,  process.entity_id
| stats occurrences = count(*) by process.entity_id, process.executable
 /* threshold can be adjusted to your env */
| where occurrences >= 50
```

## Notes

- This hunt returns a list of processes unique pids and executable paths that performs a high number of DNS TXT lookups.
- Pivoting by `process.entity_id` will allow further investigation (parent process, hash, child processes, other network events etc.).

## MITRE ATT&CK Techniques

- [T1071](https://attack.mitre.org/techniques/T1071)
- [T1071.004](https://attack.mitre.org/techniques/T1071/004)

## License

- `Elastic License v2`

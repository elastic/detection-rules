# Suspicious DNS TXT Record lookups by process

---

## Metadata

- **Author:** Elastic
- **UUID:** `0b7343f7-2d16-43c7-af28-9d1f012b1093`
- **Integration:** `logs-endpoint.events.network-*, logs-windows.sysmon_operational-*`
- **Language:** `ES|QL`

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

- This hunt returns a list of processes unique pids and executable path that performs a high number of DNS TXT lookups.
- Pivoting by process.entity_id will allow further investigation (parent process, hash, child processes, other network events etc.).
## MITRE ATT&CK Techniques

- [T1071](https://attack.mitre.org/techniques//T1071)

- [T1071.004](https://attack.mitre.org/techniques//T1071/004)

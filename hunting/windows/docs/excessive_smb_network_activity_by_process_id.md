# Excessive SMB Network Activity by process Id

---

## Metadata

- **Author:** Elastic
- **UUID:** `6949135b-76d7-47a3-ae95-ef482508fb7c`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [windows](https://docs.elastic.co/integrations/windows)
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.network-*, logs-windows.sysmon_operational-* 
| where @timestamp > now() - 7 day and 
  host.os.family == "windows" and event.category == "network" and network.direction == "egress" and 
  network.transport == "tcp"and destination.port == 445 and source.port >= 49152 and process.pid == 4
| keep destination.ip, process.entity_id, host.id
| stats count_unique_dst = count_distinct(destination.ip) by process.entity_id, host.id
 /* threshold set to 20 but can be adjusted to reduce normal baseline in your env */
| where count_unique_dst >= 20
```

## Notes

- This hunt looks for high number of SMB connections from same process to more than a defined threshold of unique destination Ip addresses. This could be a sign of SMB scanning or some lateral movement via remote services that depend on SMB protocol.
- Further investigation can done pivoting by process.entity_id and host.id.
- Maximum number of unique destination.ip by process can be adjusted to your environment to reduce normal noisy hosts by Id.
## MITRE ATT&CK Techniques

- [T1021](https://attack.mitre.org/techniques/T1021)
- [T1021.002](https://attack.mitre.org/techniques/T1021/002)

## License

- `Elastic License v2`

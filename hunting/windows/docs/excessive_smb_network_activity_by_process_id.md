# Excessive SMB Network Activity by Process ID

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt looks for a high occurrence of SMB connections from the same process by unique destination IP addresses. The number of unique destination IP addresses is compared to a defined threshold. This could be a sign of SMB scanning or lateral movement via remote services that depend on the SMB protocol.

- **UUID:** `8a95f552-f149-4c71-888e-f2690f5add15`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [windows](https://docs.elastic.co/integrations/windows)
- **Language:** `[ES|QL]`
- **Source File:** [Excessive SMB Network Activity by Process ID](../queries/excessive_smb_network_activity_by_process_id.toml)

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

- Further investigation can done pivoting by `process.entity_id` and `host.id.`
- Maximum number of unique `destination.ip` by process can be adjusted to your environment to reduce normal noisy hosts by process ID.

## MITRE ATT&CK Techniques

- [T1021](https://attack.mitre.org/techniques/T1021)
- [T1021.002](https://attack.mitre.org/techniques/T1021/002)

## License

- `Elastic License v2`

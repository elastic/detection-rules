# Excessive RDP Network Activity by Source Host - Elastic Defend - Sysmon

---

## Metadata

- **Author:** Elastic
- **UUID:** `6ff3a518-3bf4-4e7d-9a66-2ef7aaa68cfc`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [windows](https://docs.elastic.co/integrations/windows)
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.network-*, logs-windows.sysmon_operational-* 
| where  @timestamp > now() - 7 day 
| where host.os.family == "windows" and event.category == "network" and process.name == "svchost.exe" and network.direction == "ingress" and 
  network.transport == "tcp"and destination.port == 3389 and source.port >= 49152
| stats agents = count_distinct(host.id) by source.ip
| where agents >= 10
```

## Notes

- This hunt looks for high number of Remote Desktop connections from same host and user.name to more than a defined threshold of unique destination Ip addresses. This could be a sign of discovery or lateral movement via the Remote Desktop Protocol.
- Further investigation can done pivoting by host.id and user name.
- Depending on normal SysAdmin RDP activity the 10 threshold can be adjusted to reduce normal noisy activity.
## MITRE ATT&CK Techniques

- [T1021](https://attack.mitre.org/techniques/T1021)
- [T1021.001](https://attack.mitre.org/techniques/T1021/001)

## License

- `Elastic License v2`

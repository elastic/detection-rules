# Excessive RDP Network Activity by Source Host and User- Elastic Defend - Sysmon

---

## Metadata

- **Author:** Elastic
- **UUID:** `fe01a8a5-6367-4c4c-a57b-be513ab80e42`
- **Integration:** `logs-endpoint.events.network-*, logs-windows.sysmon_operational-*`
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.network-*, logs-windows.sysmon_operational-* 
| where  @timestamp > now() - 7 day 
| where host.os.family == "windows" and event.category == "network" and network.direction == "egress" and 
  network.transport == "tcp"and destination.port == 3389 and source.port >= 49152 
| keep destination.ip, host.id, user.name
| stats count_unique_dst = count_distinct(destination.ip) by host.id, user.name
 /* threshold set to 10 but can be adjusted to reduce normal baseline in your env */
| where count_unique_dst >= 10
```

## Notes

- This hunt looks for high number of Remote Desktop connections from same host and user.name to more than a defined threshold of unique destination Ip addresses. This could be a sign of discovery or lateral movement via the Remote Desktop Protocol.
- Further investigation can done pivoting by host.id and user name.
- Depending on normal SysAdmin RDP activity the 10 threshold can be adjusted to reduce normal noisy activity.
## MITRE ATT&CK Techniques

- [T1021](https://attack.mitre.org/techniques//T1021)

- [T1021.001](https://attack.mitre.org/techniques//T1021/001)

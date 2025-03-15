# Excessive RDP Network Activity by Host and User

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt looks for a high occurrence of remote desktop connections from the same host and user. The number of unique destination IP addresses is compared to a defined threshold. This could be a sign of discovery or lateral movement via the Remote Desktop Protocol (RDP).

- **UUID:** `f7d2054f-b571-4cd0-b39e-a779576e9398`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [windows](https://docs.elastic.co/integrations/windows)
- **Language:** `[ES|QL]`
- **Source File:** [Excessive RDP Network Activity by Host and User](../queries/excessive_rdp_network_activity_by_source_host_and_user.toml)

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

```sql
from logs-endpoint.events.network-*, logs-windows.sysmon_operational-*
| where  @timestamp > now() - 7 day
| where host.os.family == "windows" and event.category == "network" and process.name == "svchost.exe" and network.direction == "ingress" and
  network.transport == "tcp"and destination.port == 3389 and source.port >= 49152
| stats agents = count_distinct(host.id) by source.ip
| where agents >= 10
```

## Notes

- Further investigation can done pivoting by `host.id` and `user.name`.
- Depending on normal SysAdmin RDP activity, the threshold of 10 can be adjusted to reduce normal noisy activity.
- The second query uses Windows Security log event ID 4624 to summarize numbers of RDP connections by `source.ip` and `user.name` and duration.

## MITRE ATT&CK Techniques

- [T1021](https://attack.mitre.org/techniques/T1021)
- [T1021.001](https://attack.mitre.org/techniques/T1021/001)

## License

- `Elastic License v2`

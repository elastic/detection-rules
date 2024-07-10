# Excessive SSH Network Activity to Unique Destinations

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies excessive SSH network activity to unique destinations on Linux systems. It monitors network connections over TCP to port 22 (SSH) and counts the number of unique destination IP addresses. A high number of unique destinations could indicate suspicious activity such as discovery or lateral movement.

- **UUID:** `223f812c-a962-4d58-961d-134d8f8b15da`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL]`
- **Source File:** [Excessive SSH Network Activity to Unique Destinations](../queries/excessive_ssh_network_activity_unique_destinations.toml)

## Query

```sql
from logs-endpoint.events.network-*
| where @timestamp > now() - 7 day
| where host.os.type == "linux" and event.category == "network" and network.transport == "tcp" and destination.port == 22 and source.port >= 49152
| keep destination.ip, host.id, user.name
| stats count_unique_dst = count_distinct(destination.ip) by host.id, user.name
// Alter this threshold to make sense for your environment
| where count_unique_dst >= 10
| limit 100
| sort user.name asc
```

## Notes

- Monitors network connections to port 22 (SSH) and counts the number of unique destination IP addresses per host and user.
- A high number of unique destinations can indicate suspicious activity such as discovery or lateral movement.
- The threshold of 10 unique destinations can be adjusted to suit the environment's baseline activity.

## MITRE ATT&CK Techniques

- [T1021.004](https://attack.mitre.org/techniques/T1021/004)
- [T1078.003](https://attack.mitre.org/techniques/T1078/003)

## License

- `Elastic License v2`

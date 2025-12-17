# Low Volume External Network Connections from Process by Unique Agent

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies low volume external network connections initiated by processes on Linux systems. It focuses on connections attempted by processes that have been seen infrequently (five or fewer connections) and by unique agents. This can help identify potentially suspicious activity that might be missed due to low volume.

- **UUID:** `12526f14-5e35-4f5f-884c-96c6a353a544`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL]`
- **Source File:** [Low Volume External Network Connections from Process by Unique Agent](../queries/low_volume_external_network_connections_from_process.toml)

## Query

```sql
from logs-endpoint.events.network-*
| where @timestamp > now() - 7 day
| where host.os.type == "linux" and event.category == "network" and event.type == "start" and event.action == "connection_attempted" and not process.name is null and
    not CIDR_MATCH(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10", "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1","FE80::/10", "FF00::/8")
| stats connection_count = count(*), unique_agent_count = count_distinct(agent.id) by process.name
| where connection_count <= 5 and unique_agent_count == 1
| limit 100
| sort connection_count, unique_agent_count asc
```

```sql
from logs-endpoint.events.network-*
| where @timestamp > now() - 7 day
| where host.os.type == "linux" and event.category == "network" and event.type == "start" and event.action == "connection_attempted" and user.id == "0" and not process.name is null and
    not CIDR_MATCH(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10", "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1","FE80::/10", "FF00::/8")
| stats connection_count = count(*), unique_agent_count = count_distinct(agent.id) by process.name
| where connection_count <= 5 and unique_agent_count == 1
| limit 100
| sort connection_count, unique_agent_count asc
```

## Notes

- Monitors for network connections attempted by processes that have a low occurrence frequency (five or fewer connections) and are seen by a unique agent.
- Excludes common internal IP ranges to minimize false positives.
- A separate query is included to specifically monitor low volume network connections initiated by the root user, as these can be particularly indicative of malicious activity.

## MITRE ATT&CK Techniques

- [T1071.001](https://attack.mitre.org/techniques/T1071/001)
- [T1071.004](https://attack.mitre.org/techniques/T1071/004)

## License

- `Elastic License v2`

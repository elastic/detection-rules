# Egress Network Connections with Total Bytes Greater than Threshold

---

## Metadata

- **Author:** Elastic
- **Description:** Using aggregation and the ES|QL `SUM` function, this hunt identifies processes that performed egress connections with total bytes greater or equal to a defined maximum threshold. This may indicate exfiltration or long term command and control activity.

- **UUID:** `24925575-defd-4581-bfda-a8753dcfb46e`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL]`
- **Source File:** [Egress Network Connections with Total Bytes Greater than Threshold](../queries/potential_exfiltration_by_process_total_egress_bytes.toml)

## Query

```sql
from logs-endpoint.events.network-*
| where  @timestamp > now() - 8 hour
| where host.os.family == "windows" and event.category == "network" and
  event.action == "disconnect_received" and
  not CIDR_MATCH(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10", "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1","FE80::/10", "FF00::/8")
| keep source.bytes, destination.address, process.executable, process.entity_id
| stats total_bytes_out = sum(source.bytes) by process.entity_id, destination.address, process.executable
 /* more than 1GB out by same process.pid in 8 hours */
| where total_bytes_out >= 1073741824
```

## Notes

- This hunt is not compatible with Sysmon event 3 (Network connection) and Windows security event 5156 as both don't log `source.bytes`.
- The use of `host.os.family` is to optimise the query and avoid timeout. You can duplicate the same query for other platforms (linux, macos etc.)
- Based on limited testing it's recommended to set the query time window to 8 hours.
- Pivoting by `process.entity_id` will allow further investigation (parent process, hash, child processes, other network events etc.).

## MITRE ATT&CK Techniques

- [T1071](https://attack.mitre.org/techniques/T1071)

## License

- `Elastic License v2`

# Suspicious Network Connections by unsigned machO

---

## Metadata

- **Author:** Elastic
- **UUID:** `44aff0e3-e0d7-4dca-a94f-2dd0b96f18bd`
- **Integration:** `logs-endpoint.events.network-*`
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.network-*
| where @timestamp > now() - 7 day
| where host.os.family == "macos" and event.category == "network" and 
  (process.code_signature.exists == false or process.code_signature.trusted != true) and 
  /* excluding private IP ranges */
  not CIDR_MATCH(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10", "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1","FE80::/10", "FF00::/8")
| keep source.bytes, destination.address, process.name, process.entity_id, @timestamp
 /* calc total duration , total MB out and the number of connections per hour */
| stats total_bytes_out = sum(source.bytes), count_connections = count(*), start_time = min(@timestamp), end_time = max(@timestamp) by process.entity_id, destination.address, process.name
| eval dur = TO_DOUBLE(end_time)-TO_DOUBLE(start_time), duration_hours=TO_INT(dur/3600000), MB_out=TO_DOUBLE(total_bytes_out) / (1024*1024), number_of_con_per_hour = (count_connections / duration_hours)
| keep process.entity_id, process.name, duration_hours, destination.address, MB_out, count_connections, number_of_con_per_hour
/* threshold is set to 120 connections per minute , you can adjust it to your env/FP rate */
| where duration_hours >= 8 and number_of_con_per_hour >= 120
```

## Notes

- This hunt aggregate by process Id and destination ip the number of connections per hour over a period of time greater than a defined threshold. The process paths are scoped to Microsoft signed binaries often injected or used as a lolbin to masquerade malicious execution. This could be a sign of long term network activity to perform command and control from an injected process.
- Hunt can be extended by adding suspicious process paths or lolbins.
## MITRE ATT&CK Techniques

- [T1071](https://attack.mitre.org/techniques//T1071)


## License

- `Elastic License v2`

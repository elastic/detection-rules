# High Count of Network Connection Over Extended Period by Process

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies browser or svchost instances performing a considerable number of connections per hour over an extended period of hours to a specific destination address, limited to a unique host of the monitored agents. Browsers and svchost are both good targets for masquerading network traffic on the endpoint.

- **UUID:** `5e5aa9c2-96a8-4d5b-bbca-ff2ec8fefa5b`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [windows](https://docs.elastic.co/integrations/windows)
- **Language:** `[ES|QL]`
- **Source File:** [High Count of Network Connection Over Extended Period by Process](../queries/high_count_of_network_connection_over_extended_period_by_process.toml)

## Query

```sql
from logs-endpoint.events.network-*, logs-windows.sysmon_operational-*
| where host.os.family == "windows" and event.category == "network" and
  network.direction == "egress" and process.name in ("chrome.exe", "msedge.exe", "iexplore.exe", "firefox.exe", "svchost.exe") and
 /* excluding DNS */
 destination.port != 53 and
 /* excluding private IP ranges */
  not CIDR_MATCH(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10", "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1","FE80::/10", "FF00::/8")
| keep source.bytes, destination.address, process.name, process.entity_id, @timestamp, host.id
 /* calc total duration and the number of connections per hour */
| stats count_connections = count(*), start_time = min(@timestamp), end_time = max(@timestamp), hosts= count_distinct(host.id), count_unique_pids = count_distinct(process.entity_id) by  destination.address, process.name
| eval dur = TO_DOUBLE(end_time)-TO_DOUBLE(start_time), duration_hours=TO_INT(dur/3600000), number_of_con_per_hour = (count_connections / duration_hours)
| keep process.name, duration_hours, destination.address, hosts, count_unique_pids, count_connections, number_of_con_per_hour
 /* threshold is set to 120 connections per minute during 4 hours and limited to 1 agent and 1 pid, you can adjust this values to your hunting needs */
| where number_of_con_per_hour >= 120 and duration_hours >= 4 and hosts == 1 and count_unique_pids == 1
```

```sql
from logs-endpoint.events.network-*
| where @timestamp > now() - 7 day
| where host.os.family == "windows" and event.category == "network" and
  network.direction == "egress" and
(process.code_signature.exists == false or process.code_signature.trusted != true or starts_with(process.executable, "C:\\Users\\Public\\"))  and
 /* excluding private IP ranges */
  not CIDR_MATCH(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10", "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1","FE80::/10", "FF00::/8")
| keep source.bytes, destination.address, process.name, process.entity_id, @timestamp
 /* calc total duration , total MB out and the number of connections per hour */
| stats total_bytes_out = sum(source.bytes), count_connections = count(*), start_time = min(@timestamp), end_time = max(@timestamp) by process.entity_id, destination.address, process.name
| eval dur = TO_DOUBLE(end_time)-TO_DOUBLE(start_time), duration_hours=TO_INT(dur/3600000), MB_out=TO_DOUBLE(total_bytes_out) / (1024*1024), number_of_con_per_hour = (count_connections / duration_hours)
| keep process.entity_id, process.name, duration_hours, destination.address, MB_out, count_connections, number_of_con_per_hour
 /* threshold is set to 120 connections per minute , you can adjust it to your env/FP rate */
| where duration_hours >= 1 and number_of_con_per_hour >= 120
```

```sql
from logs-endpoint.events.network-*, logs-windows.sysmon_operational-*
| where @timestamp > now() - 7 day
| where host.os.family == "windows" and event.category == "network" and
  network.direction == "egress" and (process.executable like "C:\\\\Windows\\\\System32*" or process.executable like "C:\\\\Windows\\\\SysWOW64\\\\*")  and not user.id in ("S-1-5-19", "S-1-5-20") and
/* multiple Windows svchost services perform long term connection to MS ASN, can be covered in a dedicated hunt */
not (process.name == "svchost.exe" and user.id == "S-1-5-18") and
/* excluding private IP ranges */
  not CIDR_MATCH(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10", "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1","FE80::/10", "FF00::/8")
| keep source.bytes, destination.address, process.name, process.entity_id, @timestamp
 /* calc total duration , total MB out and the number of connections per hour */
| stats total_bytes_out = sum(source.bytes), count_connections = count(*), start_time = min(@timestamp), end_time = max(@timestamp) by process.entity_id, destination.address, process.name
| eval dur = TO_DOUBLE(end_time)-TO_DOUBLE(start_time), duration_hours=TO_INT(dur/3600000), MB_out=TO_DOUBLE(total_bytes_out) / (1024*1024), number_of_con_per_hour = (count_connections / duration_hours)
| keep process.entity_id, process.name, duration_hours, destination.address, MB_out, count_connections, number_of_con_per_hour
/* threshold is set to 120 connections per minute , you can adjust it to your env/FP rate */
| where duration_hours >= 1 and number_of_con_per_hour >= 120
```

## Notes

- This hunt includes three queries for Elastic Defend and Sysmon data sources.

## MITRE ATT&CK Techniques

- [T1071](https://attack.mitre.org/techniques/T1071)

## License

- `Elastic License v2`

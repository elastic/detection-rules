# High count of network connection over extended period by process - Elastic Defend Network - Sysmon

---

## Metadata

- **Author:** Elastic
- **UUID:** `ed254a22-e7bb-4a36-9291-196b77762dd8`
- **Integration:** `logs-endpoint.events.network-*, logs-windows.sysmon_operational-*`
- **Language:** `ES|QL`

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

## Notes

- This hunt identify browser or svchost instances performing a considerable number of connections per hour over an extended period of hours to a specific destination address and this is limited to a unique host of the monitored agents. Browsers and svchost are both good targets for masquerading network traffic on the endpoint.
## MITRE ATT&CK Techniques

- [T1071](https://attack.mitre.org/techniques//T1071)

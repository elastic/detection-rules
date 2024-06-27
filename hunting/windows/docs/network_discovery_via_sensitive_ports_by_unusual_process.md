# Network Discovery via Sensitive Ports by Unusual Process

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt looks for either processes connecting to multiple sensitive TCP ports (SMB, RDP, LDAP, Kerberos and ADWS), a high number of SMB/RDP connections to unique destinations or the same process connecting to both RDP and SMB (should be rare).

- **UUID:** `e0acab7d-30bd-4be0-9682-5c3457bbeb4f`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [windows](https://docs.elastic.co/integrations/windows)
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.network-*, logs-windows.sysmon_operational-*
| where @timestamp > now() - 7 day
| where host.os.family == "windows" and event.category == "network" and network.direction == "egress" and
  network.transport == "tcp"and destination.port in (3389, 445, 389, 9389, 88, 5985, 5986, 22) and source.port >= 49152 and
  process.pid != 4
| keep process.executable, destination.port, destination.ip, process.entity_id
 /* network events with SMB or RDP as a target */
| eval smb_dip = case(destination.port == 445, destination.ip, null), rdp_dip = case(destination.port == 389, destination.ip, null)
 /* unique count by destination.port, number of distinct SMB and RDP destinations */
| stats count_unique_ports = count_distinct(destination.port), count_smb_dst =  count_distinct(smb_dip), count_rdp_dst =  count_distinct(rdp_dip) by process.entity_id, process.executable
| where count_unique_ports >= 3 or count_rdp_dst >= 10 or count_smb_dst >= 10 or (count_rdp_dst >= 1 and count_rdp_dst >= 1)
```

## Notes

- The query thresholds for SMB or RDP need to be adjusted to your environment.
- You can add more sensitive ports to the list like FTP, SSH and others.
- Elastic Network events include process code signature information, this can be added to filter out signed third party false positives.
## MITRE ATT&CK Techniques

- [T1021](https://attack.mitre.org/techniques/T1021)
- [T1021.002](https://attack.mitre.org/techniques/T1021/002)
- [T1021.001](https://attack.mitre.org/techniques/T1021/001)

## License

- `Elastic License v2`

# Execution via Windows Services with low occurrence frequency - Elastic Defend - Sysmon

---

## Metadata

- **Author:** Elastic
- **UUID:** `858b7022-b587-4b95-afd6-8ce597bedce3`
- **Integration:** `logs-endpoint.events.process-*, logs-windows.sysmon_operational-*`
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.process-*, logs-windows.sysmon_operational-*
| where  @timestamp > now() - 7 day
| where host.os.family == "windows" and event.category == "process" and event.action in ("start", "Process creation") and 
  process.parent.name == "services.exe" and process.code_signature.trusted != true
| stats hosts = count_distinct(host.id) by process.hash.sha256, process.name
 /* unique hash observed in one unique agent */
| where hosts == 1
```

## Notes

- Windows security event 4688 lacks code signature and hash information, hence the use of process.executable for aggregation.
- Unique process.hash.sha256 and agent is not necessarily malicious, this help surface ones worth further investigation.
- Suspicious process.executable paths and lolbins should be reviewed further.
## MITRE ATT&CK Techniques

- [T1543](https://attack.mitre.org/techniques//T1543)

- [T1543.003](https://attack.mitre.org/techniques//T1543/003)


## License

- `Elastic License v2`

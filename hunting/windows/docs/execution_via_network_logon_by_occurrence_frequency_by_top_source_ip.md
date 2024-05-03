# Execution via Network Logon by occurrence frequency by top Source IP

---

## Metadata

- **Author:** Elastic
- **UUID:** `ae07c580-290e-4421-add8-d6ca30509b6a`
- **Integration:** `logs-endpoint.events.process-*`
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.process-*
| where  @timestamp > now() - 7 day and where host.os.family == "windows" and 
  event.category == "process" and event.action == "start" and 
  /* network logon type and the execution is within 30 seconds of the logon time */
  process.Ext.session_info.logon_type == "Network" and process.Ext.session_info.relative_logon_time <= 30
| stats total = count(*) by process.Ext.session_info.client_address, user.name
 /* sort by top source.ip and account */
| sort total desc
```

## Notes

- process.Ext.session_info.* is populated for Elastic Defend version 8.6 and above.
- Execution via legit Microsoft processes like powershell and cmd need to further investigated via aggregation by process.command_line.
- Aggregation can be also done by process.executable, normalizing process path by removing random patterns using the REPLACE function via regex.
## MITRE ATT&CK Techniques

- [T1021](https://attack.mitre.org/techniques//T1021)

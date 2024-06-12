# Execution via Network Logon by occurrence frequency

---

## Metadata

- **Author:** Elastic
- **UUID:** `fd3f9982-fd8c-4f0f-bbe6-e589752c34db`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.process-*
| where  @timestamp > now() - 7 day and host.os.family == "windows" and 
  event.category == "process" and event.action == "start" and 
  /* network logon type and the execution is within 30 seconds of the logon time */
  process.Ext.session_info.logon_type == "Network" and process.Ext.session_info.relative_logon_time <= 30
| stats total = count(*), hosts = count_distinct(host.id) by process.hash.sha256, process.Ext.session_info.client_address, user.name, process.parent.name
 /* unique hash limited to one host and number of execution is 1 */
| where  hosts == 1 and total == 1
```

## Notes

- process.Ext.session_info.* is populated for Elastic Defend version 8.6 and above.
- Execution via legit Microsoft processes like powershell and cmd need to further investigated via aggregation by process.command_line.
- Aggregation can be also done by process.executable, normalizing process path by removing random patterns using the REPLACE function via regex.
## MITRE ATT&CK Techniques

- [T1021](https://attack.mitre.org/techniques/T1021)

## License

- `Elastic License v2`

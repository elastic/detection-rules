# Execution via Remote Services by Client Address

---

## Metadata

- **Author:** Elastic
- **UUID:** `e6e54717-2676-4785-a4a6-503577bfb0ea`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.process-*
| where  @timestamp > now() - 7 day and where host.os.family == "windows" and 
  event.category == "process" and event.action == "start" and 
  /* network logon type */
  process.Ext.session_info.logon_type == "Network" and 
  (process.parent.name .caseless in ("wmiprvse.exe", "wsmprovhost.exe", "winrshost.exe") or (process.parent.name == "svchost.exe" and process.parent.args == "DcomLaunch"))
| stats total = count(*), hosts = count_distinct(host.id) by process.Ext.session_info.client_address, user.name, process.parent.name
 /* sort by top source.ip and account */
| sort total desc
```

## Notes

- process.Ext.session_info.* is populated for Elastic Defend version 8.6 and above.
## MITRE ATT&CK Techniques

- [T1021](https://attack.mitre.org/techniques/T1021)
- [T1021.003](https://attack.mitre.org/techniques/T1021/003)
- [T1021.006](https://attack.mitre.org/techniques/T1021/006)
- [T1047](https://attack.mitre.org/techniques/T1047)

## License

- `Elastic License v2`

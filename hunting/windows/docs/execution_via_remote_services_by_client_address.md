# Execution via Remote Services by Client Address

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt aggregates process execution via remote network logon by source address, account name and where the parent process is related to remote services such as WMI, WinRM, DCOM and remote PowerShell. This may indicate lateral movement via remote services.

- **UUID:** `5fd5da54-0515-4d6b-b8d7-30fd05f5be33`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL]`
- **Source File:** [Execution via Remote Services by Client Address](../queries/execution_via_remote_services_by_client_address.toml)

## Query

```sql
from logs-endpoint.events.process-*
| where  @timestamp > now() - 7 day and host.os.family == "windows" and
  event.category == "process" and event.action == "start" and
  /* network logon type */
  process.Ext.session_info.logon_type == "Network" and
  (process.parent.name .caseless in ("wmiprvse.exe", "wsmprovhost.exe", "winrshost.exe") or (process.parent.name == "svchost.exe" and process.parent.args == "DcomLaunch"))
| stats total = count(*), hosts = count_distinct(host.id) by process.Ext.session_info.client_address, user.name, process.parent.name
 /* sort by top source.ip and account */
| sort total desc
```

## Notes

- `process.Ext.session_info.*` is populated for Elastic Defend versions 8.6.0+.

## MITRE ATT&CK Techniques

- [T1021](https://attack.mitre.org/techniques/T1021)
- [T1021.003](https://attack.mitre.org/techniques/T1021/003)
- [T1021.006](https://attack.mitre.org/techniques/T1021/006)
- [T1047](https://attack.mitre.org/techniques/T1047)

## License

- `Elastic License v2`

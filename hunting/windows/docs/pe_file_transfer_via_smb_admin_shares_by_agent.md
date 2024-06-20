# PE File Transfer via SMB_Admin Shares by Agent

---

## Metadata

- **Author:** Elastic
- **UUID:** `3e66fc1a-2ea0-43a6-ba51-0280c693d152`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.file-*
| where  @timestamp > now() - 7 day 
| where host.os.family == "windows" and event.category == "file" and event.action != "deletion" and process.pid == 4 and 
  starts_with(file.Ext.header_bytes, "4d5a*") and (starts_with(user.id, "S-1-5-21-") or starts_with(user.id, "S-1-12-1-")) 
| stats agents = count_distinct(host.id), total = count(*) by user.name
| where agents == 1 and total <= 3
```

## Notes

- This hunt looks for high number of executable file transfer via the SMB protocol by the same user.name to more than a defined maxium threshold of targets. This could be a sign of lateral movement via the Windows Admin Shares.
- Further investigation can done pivoting by host.id and user name.
## MITRE ATT&CK Techniques

- [T1021](https://attack.mitre.org/techniques/T1021)
- [T1021.002](https://attack.mitre.org/techniques/T1021/002)

## License

- `Elastic License v2`

# PE File Transfer via SMB_Admin Shares by Agent or User

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt looks for a high number of executable file transfers via the SMB protocol by the same user or agent to more than a defined maxium threshold of targets. This could be a sign of lateral movement via the Windows Admin Shares.

- **UUID:** `814894a4-c951-4f33-ab0b-09354e1cb957`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL]`
- **Source File:** [PE File Transfer via SMB_Admin Shares by Agent or User](../queries/pe_file_transfer_via_smb_admin_shares_by_agent.toml)

## Query

```sql
from logs-endpoint.events.file-*
| where  @timestamp > now() - 7 day
| where host.os.family == "windows" and event.category == "file" and event.action != "deletion" and process.pid == 4 and
  starts_with(file.Ext.header_bytes, "4d5a*") and (starts_with(user.id, "S-1-5-21-") or starts_with(user.id, "S-1-12-1-"))
| stats agents = count_distinct(host.id), total = count(*) by user.name
| where agents == 1 and total <= 3
```

```sql
from logs-endpoint.events.file-*
| where  @timestamp > now() - 7 day
| where host.os.family == "windows" and event.category == "file" and event.action != "deletion" and process.pid == 4 and
  starts_with(file.Ext.header_bytes, "4d5a*") and (starts_with(user.id, "S-1-5-21-") or starts_with(user.id, "S-1-12-1-"))
| stats agents = count_distinct(host.id), total = count(*) by user.name
 /* threshold set to 10 but can be adjusted to reduce normal baseline in your env */
| where agents >= 10
```

## Notes

- Further investigation can done pivoting by `host.id` and `user.name`.

## MITRE ATT&CK Techniques

- [T1021](https://attack.mitre.org/techniques/T1021)
- [T1021.002](https://attack.mitre.org/techniques/T1021/002)

## License

- `Elastic License v2`

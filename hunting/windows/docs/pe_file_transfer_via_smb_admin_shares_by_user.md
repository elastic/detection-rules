# PE File Transfer via SMB_Admin Shares by User

---

## Metadata

- **Author:** Elastic
- **UUID:** `ef9def35-0671-4599-8a18-5a1b833ef4c4`
- **Integration:** `logs-endpoint.events.file-*`
- **Language:** `ES|QL`

## Query

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

- This hunt looks for high number of executable file transfer via the SMB protocol by the same user.name to more than a defined maxium threshold of targets. This could be a sign of lateral movement via the Windows Admin Shares.
- PE File Transfer via SMB/Admin Shares by User
## MITRE ATT&CK Techniques

- [T1021](https://attack.mitre.org/techniques//T1021)

- [T1021.002](https://attack.mitre.org/techniques//T1021/002)


## License

- `Elastic License v2`

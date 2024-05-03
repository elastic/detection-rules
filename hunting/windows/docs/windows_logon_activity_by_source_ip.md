# Windows logon activity by source IP

---

## Metadata

- **Author:** Elastic
- **UUID:** `7bdea198-eb09-4eca-ae3d-bfc3b52c89a9`
- **Integration:** `logs-system.security-*`
- **Language:** `ES|QL`

## Query

```sql
from logs-system.security-*
| where  @timestamp > now() - 7 day
| where host.os.family == "windows" and 
  event.category == "authentication" and event.action in ("logon-failed", "logged-in") and winlog.logon.type == "Network" and 
  source.ip is not null and 
  /* noisy failure status codes often associated to authentication misconfiguration */ 
  not (event.action == "logon-failed" and winlog.event_data.Status in ("0xC000015B", "0XC000005E", "0XC0000133", "0XC0000192"))
| eval failed = case(event.action == "logon-failed", source.ip, null), success = case(event.action == "logged-in", source.ip, null)
| stats count_failed = count(failed), count_success = count(success), count_user = count_distinct(winlog.event_data.TargetUserName) by source.ip
 /* below threshold should be adjusted to your env logon patterns */
| where count_failed >= 100 and count_success <= 10 and count_user >= 20
```

## Notes

- This hunt return the total number of failed logons, successful ones and the number of unique account names grouped by source.ip.
- Pay close attention to IP addresses source of a high number of failures associated with low success attempts and high number of used accounts.
## MITRE ATT&CK Techniques

- [T1110](https://attack.mitre.org/techniques/T1110)
- [T1110.001](https://attack.mitre.org/techniques/T1110/001)
- [T1110.003](https://attack.mitre.org/techniques/T1110/003)

## License

- `Elastic License v2`

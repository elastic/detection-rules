# Windows Logon Activity by Source IP

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt returns a summary of network logon activity by `source.ip` using Windows event IDs 4624 and 4625. The higher the number of failures, low success and multiple accounts the more suspicious the behavior is.

- **UUID:** `441fba85-47a9-4f1f-aab4-569bbfdc548b`
- **Integration:** [system](https://docs.elastic.co/integrations/system)
- **Language:** `[ES|QL]`
- **Source File:** [Windows Logon Activity by Source IP](../queries/windows_logon_activity_by_source_ip.toml)

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

- Pay close attention to IP address sources with a high number of failed connections associated with low success attempts and high number of user accounts.

## MITRE ATT&CK Techniques

- [T1110](https://attack.mitre.org/techniques/T1110)
- [T1110.001](https://attack.mitre.org/techniques/T1110/001)
- [T1110.003](https://attack.mitre.org/techniques/T1110/003)

## License

- `Elastic License v2`

# Logon Activity by Source IP

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies unusual logon activity by source IP on Linux systems. It monitors authentication events, focusing on failed logon attempts from specific IP addresses. A high number of failed logon attempts combined with a low number of successful logons and multiple distinct usernames can indicate a potential brute force or credential stuffing attack.

- **UUID:** `95c1467d-d566-4645-b5f1-37a4b0093bb6`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL]`
- **Source File:** [Logon Activity by Source IP](../queries/login_activity_by_source_address.toml)

## Query

```sql
from logs-system.auth-*
| mv_expand event.category
| where @timestamp > now() - 7 day
| where host.os.type == "linux" and event.category == "authentication" and event.action in ("ssh_login", "user_login") and
  event.outcome in ("failure", "success") and source.ip is not null and
  not CIDR_MATCH(source.ip, "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "::1")
| eval failed = case(event.outcome == "failure", source.ip, null), success = case(event.outcome == "success", source.ip, null)
| stats count_failed = count(failed), count_success = count(success), count_user = count_distinct(user.name) by source.ip
/* below threshold should be adjusted to your env logon patterns */
| where count_failed >= 100 and count_user >= 20
```

## Notes

- Monitors authentication events and counts failed and successful logon attempts by source IP address.
- A high number of failed logon attempts combined with a low number of successful logons and multiple distinct usernames can indicate a potential brute force or credential stuffing attack.
- The thresholds for failed attempts, successful logons, and distinct usernames should be adjusted based on the environment's normal logon patterns.

## MITRE ATT&CK Techniques

- [T1110](https://attack.mitre.org/techniques/T1110)
- [T1078](https://attack.mitre.org/techniques/T1078)

## License

- `Elastic License v2`

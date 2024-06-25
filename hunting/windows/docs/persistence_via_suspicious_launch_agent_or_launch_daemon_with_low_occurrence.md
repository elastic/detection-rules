# Low Occurrence of Suspicious Launch Agent or Launch Daemon

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt looks for persistence via Launch agent or daemon where the distribution is limited to one unique host.

- **UUID:** `a7dcd1a1-2860-491e-8802-31169a607167`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.file-*
| where  @timestamp > now() - 7 day
| where host.os.family == "macos" and event.category == "file" and event.action == "launch_daemon" and
  (Persistence.runatload == true or Persistence.keepalive == true) and process.executable is not null
| eval args = MV_CONCAT(Persistence.args, ",")
 /* normalizing users home profile */
| eval args = replace(args, """/Users/[a-zA-Z0-9ñ\.\-\_\$~ ]+/""", "/Users/user/")
| stats agents = count_distinct(host.id), total = count(*) by process.name, Persistence.name, args
| where starts_with(args, "/") and agents == 1 and total == 1
```

## Notes

- Further investigation can done pivoting by `Persistence.name` and `args`.
## MITRE ATT&CK Techniques

- [T1547](https://attack.mitre.org/techniques/T1547)
- [T1547.011](https://attack.mitre.org/techniques/T1547/011)
- [T1543](https://attack.mitre.org/techniques/T1543)
- [T1543.001](https://attack.mitre.org/techniques/T1543/001)
- [T1543.004](https://attack.mitre.org/techniques/T1543/004)

## License

- `Elastic License v2`

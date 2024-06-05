# Execution via Windows Services with low occurrence frequency - Windows Security

---

## Metadata

- **Author:** Elastic
- **UUID:** `5fdc9f73-c6a4-4ea4-8e16-347ed675e236`
- **Integration:** [system](https://docs.elastic.co/integrations/system)
- **Language:** `ES|QL`

## Query

```sql
from logs-system.security-*
| where  @timestamp > now() - 7 day
| where host.os.family == "windows" and event.category == "process" and event.code == "4688" and 
  event.action == "created-process" and process.parent.name == "services.exe"
| eval process_path = replace(process.executable, """([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|ns[a-z][A-Z0-9]{3,4}\.tmp|DX[A-Z0-9]{3,4}\.tmp|7z[A-Z0-9]{3,5}\.tmp|[0-9\.\-\_]{3,})""", "")
| eval process_path = replace(process_path, """[cC]:\\[uU][sS][eE][rR][sS]\\[a-zA-Z0-9\.\-\_\$~]+\\""", "C:\\\\users\\\\user\\\\")
| stats hosts = count_distinct(host.id) by process_path
 /* unique path observed in one unique agent */
| where hosts == 1
```

## Notes

- Windows security event 4688 lacks code signature and hash information, hence the use of process.executable for aggregation.
- Unique process.hash.sha256 and agent is not necessarily malicious, this help surface ones worth further investigation.
- Suspicious process.executable paths and lolbins should be reviewed further.
## MITRE ATT&CK Techniques

- [T1543](https://attack.mitre.org/techniques/T1543)
- [T1543.003](https://attack.mitre.org/techniques/T1543/003)

## License

- `Elastic License v2`

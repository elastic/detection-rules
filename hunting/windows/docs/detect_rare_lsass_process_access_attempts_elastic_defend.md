# Detect Rare LSASS Process Access Attempts - Elastic Defend

---

## Metadata

- **Author:** Elastic
- **UUID:** `3978e183-0b70-4e1c-8c40-24e367f6db5a`
- **Integration:** `logs-endpoint.events.api*`
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.api*
| where  @timestamp > NOW() - 7 day
| where event.category == "api" and host.os.family == "windows" and process.Ext.api.name in ("OpenProcess", "OpenThread", "ReadProcessMemory") and
 Target.process.name == "lsass.exe"
| keep process.executable.caseless, host.id
 /* normalize process paths to reduce known random patterns in process.executable */
| eval process = replace(process.executable.caseless, """([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|ns[a-z][A-Z0-9]{3,4}\.tmp|DX[A-Z0-9]{3,4}\.tmp|7z[A-Z0-9]{3,5}\.tmp|[0-9\.\-\_]{3,})""", "")
| stats occurences = count(process), agents = count_distinct(host.id) by process
| where agents == 1 and occurences <= 10
```

## Notes

- Based on the process.executable and process.name you can pivot and investigate further the matching instances.
- Potential false positives include rare legit condition that may trigger this behavior due to third party software or Lsass crash.
## MITRE ATT&CK Techniques

- [T1003](https://attack.mitre.org/techniques/T1003)
- [T1003.001](https://attack.mitre.org/techniques/T1003/001)

## License

- `Elastic License v2`

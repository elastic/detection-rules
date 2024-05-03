# Drivers Load with low occurrence frequency - Elastic Defend

---

## Metadata

- **Author:** Elastic
- **UUID:** `99818ad6-c242-4da7-a41a-df64fe7314d6`
- **Integration:** `logs-endpoint.events.library-*`
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.library-* 
| where @timestamp > now() - 15 day
| where host.os.family == "windows" and event.category == "driver" and event.action == "load" and dll.Ext.relative_file_creation_time <= 900
| stats host_count = count_distinct(host.id), total_count = count(*), hash_count = count_distinct(dll.hash.sha256) by dll.name, dll.pe.imphash
| where host_count == 1 and total_count == 1 and hash_count == 1
```

## Notes

- This hunt helps identify drivers loaded once, on a unique host and with a unique hash over a 15 days period of time. Further investigation can be done pivoting by dll.pe.imphash or dll.name. Advanced adversaries may leverage legit vulnerable driver to tamper with existing defences or execute code in Kernel mode.
- dll.Ext.relative_file_creation_time is used in the first query to limit the result to recently dropped drivers (populated in Elastic Defend).
- aggregation can be done also by dll.hash.sha256 / file.hash.sha256 but will return more results.
- Bring Your Own Vulnerable Driver (BYOVD) are all signed and not malicious, further investigation should be done to check the surrounding events (service creation, process that dropped the driver etc.).
## MITRE ATT&CK Techniques

- [T1068](https://attack.mitre.org/techniques//T1068)


## License

- `Elastic License v2`

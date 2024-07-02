# Hidden Process Execution

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies hidden process executions on Linux systems. It detects processes executed from hidden files, which are often used by malicious actors to conceal their activities. By focusing on hidden files rather than directories, this hunt aims to catch stealthy processes while minimizing noise.

- **UUID:** `d7a1d5b4-1234-4d5d-a68f-be123ab80e56`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL]`

## Query

```sql
from logs-endpoint.events.process-*
| where @timestamp > now() - 180 day
| where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  (process.executable rlike "/[^/]+/\\.[^/]+")
)
| stats process_count = count(process.executable), parent_process_count = count(process.parent.executable), host_count = count(host.name) by process.executable, process.parent.executable, host.name, user.id
// Alter this threshold to make sense for your environment
| where (process_count <= 3 or parent_process_count <= 3) and host_count <= 3
| sort process_count asc
| limit 100
```

## Notes

- Included only hidden files, excluding hidden directories, as hidden directories are common in Unix.
- Included a process or parent process count of <= 3, and a host count of <= 3 to eliminate common processes across different hosts.
## MITRE ATT&CK Techniques

- [T1036.004](https://attack.mitre.org/techniques/T1036/004)
- [T1059](https://attack.mitre.org/techniques/T1059)

## License

- `Elastic License v2`

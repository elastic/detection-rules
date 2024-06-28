# Unusual Process Command Lines for Web Server User

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies unusual process command lines executed by commonly used web server user accounts on Linux systems. By counting process command lines and host occurrences, this query minimizes false positives from common web server command executions while capturing true positive detections of suspicious activity.

- **UUID:** `g0a1d7e7-7890-4g0g-a71g-be456ab80e89`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.process-*
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.type == "start" and user.name in ("www-data", "apache", "nginx", "httpd", "tomcat", "lighttpd", "glassfish", "weblogic")
| stats process_cli_count = count(process.command_line), host_count = count(host.name) by process.command_line, process.name, user.name, host.name
| where process_cli_count <= 3 and host_count <= 2
| sort process_cli_count asc
| limit 100
```

## Notes

- Detects process command executions through commonly used web server user accounts such as www-data, apache, nginx, httpd, tomcat, lighttpd, glassfish, and weblogic.
- Uses process command line counting in conjunction with host counting to minimize false positives caused by common web server command executions.
- While some false positives may remain, they can be easily mitigated on an environment-specific basis.
## MITRE ATT&CK Techniques

- [T1059.001](https://attack.mitre.org/techniques/T1059/001)
- [T1071.001](https://attack.mitre.org/techniques/T1071/001)

## License

- `Elastic License v2`

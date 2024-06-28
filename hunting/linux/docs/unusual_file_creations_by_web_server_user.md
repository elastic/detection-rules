# Unusual File Creations by Web Server User

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies unusual file creations by commonly used web server user accounts on Linux systems. It focuses on file creation events in directories frequently associated with web servers and temporary storage, such as /var/www, /var/tmp, /tmp, and /dev/shm. The query aims to detect potentially suspicious activity while minimizing false positives.

- **UUID:** `h1a1d8e8-8901-4h1h-a72h-be567ab80f90`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.file-*
| where @timestamp > now() - 50 day
| where host.os.type == "linux" and event.type == "creation" and user.name in ("www-data", "apache", "nginx", "httpd", "tomcat", "lighttpd", "glassfish", "weblogic") and (
  file.path like "/var/www/*" or
  file.path like "/var/tmp/*" or
  file.path like "/tmp/*" or
  file.path like "/dev/shm/*"
)
| stats file_count = count(file.path), host_count = count(host.name) by file.path, host.name, process.name, user.name
// Alter this threshold to make sense for your environment
| where file_count <= 5
| sort file_count asc
| limit 100
```

## Notes

- Detects file creation events by web server user accounts such as www-data, apache, nginx, httpd, tomcat, lighttpd, glassfish, and weblogic.
- Monitors file creation in directories /var/www, /var/tmp, /tmp, and /dev/shm.
- This query may be better suited as a detection rule or an endpoint rule if made more specific.
## MITRE ATT&CK Techniques

- [T1036.004](https://attack.mitre.org/techniques/T1036/004)
- [T1070](https://attack.mitre.org/techniques/T1070)

## License

- `Elastic License v2`

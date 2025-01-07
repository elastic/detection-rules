# Persistence via System V Init

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies potential persistence mechanisms via System V Init on Linux systems. System V Init is a legacy init system used in many Linux distributions. System V Init uses scripts in /etc/init.d/ to start and stop services. These queries monitor for file creation/modification and process execution events in directories and files associated with System V Init services. These activities can indicate attempts to establish persistence through System V Init configurations. The hunt lists detailed information for further analysis and investigation.

- **UUID:** `27d76f07-7dc4-49bc-b4a7-6d9a01de171f`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL, SQL]`
- **Source File:** [Persistence via System V Init](../queries/persistence_via_sysv_init.toml)

## Query

```sql
from logs-endpoint.events.file-*
| where @timestamp > NOW() - 30 day
| where host.os.type == "linux" and event.type in ("creation", "change") and file.path like "/etc/init.d/*" and
not process.name in ("dpkg", "dockerd", "yum", "dnf", "snapd", "pacman")
| eval persistence = case(file.path like "/etc/init.d/*", process.name, null)
| stats pers_count = count(persistence), agent_count = count_distinct(agent.id) by process.executable, file.path
| where pers_count > 0 and pers_count <= 20 and agent_count <= 3
| sort pers_count asc
| limit 100
```

```sql
from logs-endpoint.events.process-*
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.parent.executable like "/etc/init.d/*"
| stats cc = count(), host_count = count_distinct(host.name) by process.executable, process.parent.executable
| where cc > 0 and cc <= 20 and host_count <= 3
| sort cc asc
| limit 100
```

```sql
SELECT name, path, source, status, type FROM startup_items
WHERE type == "systemd unit" AND status == "active" AND
source LIKE "/etc/init.d/%"
```

```sql
SELECT 
    f.filename, 
    f.path, 
    u.username AS file_owner, 
    g.groupname AS group_owner, 
    datetime(f.atime, 'unixepoch') AS file_last_access_time, 
    datetime(f.mtime, 'unixepoch') AS file_last_modified_time, 
    datetime(f.ctime, 'unixepoch') AS file_last_status_change_time, 
    datetime(f.btime, 'unixepoch') AS file_created_time, 
    f.size AS size_bytes,
    h.md5 
FROM 
    file f 
LEFT JOIN 
    users u ON f.uid = u.uid 
LEFT JOIN 
    groups g ON f.gid = g.gid 
LEFT JOIN 
    hash h ON f.path = h.path 
WHERE 
    f.directory IN ('/etc/init.d/')
ORDER BY 
    f.mtime DESC;
```

## Notes

- This hunt includes multiple ES|QL and OSQuery queries to identify potential persistence mechanisms via System V Init on Linux systems.
- Detects file creation or modification events in directories and files associated with System V Init services, such as /etc/init.d/.
- Detects processes started by System V Init scripts in /etc/init.d/.
- Uses OSQuery to detect active System V Init services and retrieve detailed file information related to System V Init services.
- Uses OSQuery to retrieve file information for files in /etc/init.d/.
- Excludes common legitimate processes and file types to minimize false positives.

## MITRE ATT&CK Techniques

- [T1037](https://attack.mitre.org/techniques/T1037)

## License

- `Elastic License v2`

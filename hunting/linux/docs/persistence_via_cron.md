# Persistence via Cron

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies potential persistence mechanisms via cron on Linux systems. It monitors for file creation or modification events related to cron configurations and processes spawned by cron, fcron, or atd. These activities can indicate attempts to establish persistence through scheduled tasks.

- **UUID:** `e1cffb7c-4acf-4e7a-8d72-b8b7657cf7b8`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL, SQL]`
- **Source File:** [Persistence via Cron](../queries/persistence_via_cron.toml)

## Query

```sql
from logs-endpoint.events.file-*
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.type in ("creation", "change") and (
    file.path in ("/etc/cron.allow", "/etc/cron.deny", "/etc/crontab") or
    file.path like "/etc/cron.*/*" or
    file.path like "/var/spool/cron/crontabs/*" or
    file.path like "/var/spool/anacron/*" or
    file.path like "/var/spool/cron/atjobs/*" or
    file.path like "/var/spool/fcron/*" or
    file.path like "/home/*/.tsp/*"
) and not (
    process.name in ("dpkg", "dockerd", "yum", "dnf", "snapd", "pacman", "pamac-daemon", "anacron") or
    file.extension in ("dpkg-remove", "swx", "swp") or
    file.name like "tmp.*"
)
| eval persistence = case(
    file.path in ("/etc/cron.allow", "/etc/cron.deny", "/etc/crontab") or
    file.path like "/etc/cron.*/*" or
    file.path like "/var/spool/cron/crontabs/*" or
    file.path like "/var/spool/anacron/*" or
    file.path like "/var/spool/cron/atjobs/*" or
    file.path like "/var/spool/fcron/*" or
    file.path like "/home/*/.tsp/*",
    process.name,
    null
)
| stats pers_count = count(persistence), agent_count = count_distinct(agent.id) by process.executable, file.path
| where pers_count > 0 and pers_count <= 20 and agent_count <= 3
| sort pers_count asc
| limit 100
```

```sql
from logs-endpoint.events.process-*
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.action == "exec" and event.type == "start" and process.parent.name in ("cron", "fcron", "atd")
| stats cc = count(), host_count = count_distinct(host.id) by process.command_line
| where host_count <= 3
| sort cc asc
| limit 100
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
    f.size AS size_bytes
FROM
    file f
LEFT JOIN
    users u ON f.uid = u.uid
LEFT JOIN
    groups g ON f.gid = g.gid
WHERE
    f.path IN ("/etc/cron.allow", "/etc/cron.deny", "/etc/crontab")
    OR f.path LIKE "/etc/cron.%/*"
    OR f.path LIKE "/var/spool/cron/crontabs/%"
    OR f.path LIKE "/var/spool/anacron/%"
    OR f.path LIKE "/var/spool/cron/atjobs/%"
    OR f.path LIKE "/var/spool/fcron/%"
    OR f.path LIKE "/home/%/.tsp/%"
    OR f.path LIKE "/etc/cron.allow.d/%"
    OR f.path LIKE "/etc/cron.d/%"
    OR f.path LIKE "/etc/cron.hourly/%"
    OR f.path LIKE "/etc/cron.daily/%"
    OR f.path LIKE "/etc/cron.weekly/%"
    OR f.path LIKE "/etc/cron.monthly/%"
```

```sql
SELECT * FROM crontab
```

## Notes

- This hunt includes multiple ES|QL and OSQuery queries to identify potential persistence mechanisms via cron on Linux systems.
- Detects file creation or modification events in directories and files associated with cron configurations, such as /etc/cron.allow, /etc/cron.deny, /etc/crontab, all /etc/cron.* directories and various /var/spool directories.
- Excludes common legitimate processes and file types to minimize false positives.
- Uses EVAL to tag potential persistence events and counts occurrences to identify unusual activity.
- Monitors processes started by cron, fcron, or atd to detect potential persistence mechanisms.
- OSQuery queries are provided to complement the detection by retrieving detailed file information and crontab entries.

## MITRE ATT&CK Techniques

- [T1053.003](https://attack.mitre.org/techniques/T1053/003)
- [T1053.005](https://attack.mitre.org/techniques/T1053/005)

## License

- `Elastic License v2`

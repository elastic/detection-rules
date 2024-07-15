# Persistence via Message-of-the-Day

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies potential persistence mechanisms via the message-of-the-day (motd) on Linux systems. It monitors for file creation or modification events in the /etc/update-motd.d directory and processes started by these motd scripts. These scripts launch on SSH/terminal connection events, and execute the scripts as root. These activities can indicate attempts to establish persistence through motd modifications.

- **UUID:** `5984a354-d76c-43e6-bdd9-228456f1b371`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL, SQL]`
- **Source File:** [Persistence via Message-of-the-Day](../queries/persistence_via_message_of_the_day.toml)

## Query

```sql
from logs-endpoint.events.file-*
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.type in ("creation", "change") and file.path like "/etc/update-motd.d/*" and
not process.name in ("dpkg", "dockerd", "yum", "dnf", "snapd", "pacman")
| eval persistence = case(file.path like "/etc/update-motd.d/*", process.name, null)
| stats pers_count = count(persistence), agent_count = count_distinct(agent.id) by process.executable, file.path
| where pers_count > 0 and pers_count <= 20 and agent_count <= 5
| sort pers_count asc
| limit 100
```

```sql
from logs-endpoint.events.process-*
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.action == "exec" and event.type == "start" and process.parent.executable like "/etc/update-motd.d/*" and
not process.args like "/tmp/tmp.*"
| stats cc = count(), host_count = count_distinct(host.name) by process.executable, process.parent.executable
| where host_count <= 5
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
    f.directory IN ('/etc/update-motd.d/')
ORDER BY
    f.mtime DESC;
```

## Notes

- This hunt includes multiple ES|QL and OSQuery queries to identify potential persistence mechanisms via the message-of-the-day (motd) on Linux systems.
- Detects file creation or modification events in the /etc/update-motd.d directory, which is used for message-of-the-day scripts.
- Excludes common legitimate processes to minimize false positives.
- Uses EVAL to tag potential persistence events and counts occurrences to identify unusual activity.
- Monitors processes started by motd scripts to detect potential persistence mechanisms.
- OSQuery query is provided to complement the detection by retrieving detailed file information related to motd scripts.

## MITRE ATT&CK Techniques

- [T1036.005](https://attack.mitre.org/techniques/T1036/005)
- [T1546.003](https://attack.mitre.org/techniques/T1546/003)

## License

- `Elastic License v2`

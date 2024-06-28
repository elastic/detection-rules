# Git Hook/Pager Persistence

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies potential persistence mechanisms via Git hooks and configurations on Linux systems. It monitors file creation or modification events in Git configuration and hook directories, as well as processes started by Git hooks. These activities can indicate attempts to establish persistence through Git configurations. The hunt lists detailed information for further analysis and investigation.

- **UUID:** `f3a3d0c0-3456-4f3f-a03f-be901ab80g34`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.file-*
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.type in ("creation", "change") and (
    file.path == "/etc/gitconfig" or
    file.path like "*/.git/config" or
    file.path like "/home/*/.gitconfig" or
    file.path like "*/.git/hooks/*"
) and process.name != "git"
| eval persistence = case(
    file.path == "/etc/gitconfig" or
    file.path like "*/.git/config" or
    file.path like "/home/*/.gitconfig" or
    file.path like "*/.git/hooks/*",
    process.name,
    null
)
| stats cc = count(*), pers_count = count(persistence), agent_count = count(agent.id) by process.executable, file.path, host.name, user.name
| where pers_count > 0 and pers_count <= 20 and agent_count <= 4
| sort cc asc
```

```sql
from logs-endpoint.events.process-*
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.action == "exec" and event.type == "start" and process.parent.executable like "*.git/hooks/*"
| stats process_cli_count = count(process.command_line), process_count = count(process.executable), host_count = count_distinct(host.name) by process.parent.executable, process.executable
| where host_count <= 5 and process_count < 50
| sort process_cli_count asc
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
    datetime(f.ctime, 'unixepoch') AS file_last_status change time,
    datetime(f.btime, 'unixepoch') AS file created time,
    f.size AS size bytes
FROM
    file f
LEFT JOIN
    users u ON f.uid = u.uid
LEFT JOIN
    groups g ON f.gid = g.gid
WHERE
    f.path == '/etc/gitconfig'
    OR f.path LIKE '/%%/.git/config'
    OR f.path LIKE '/home/%/.gitconfig'
    OR f.path LIKE '/%%/.git/hooks/%'
    OR f.path LIKE '/%%/%%/.git/hooks/%'
    OR f.path LIKE '/%%/%%/%%/.git/hooks/%'
    OR f.path LIKE '/%%/%%/%%/%%/.git/hooks/%'
```

## Notes

- Monitors for file creation or modification events in Git configuration and hook directories such as /etc/gitconfig, .git/config, /home/*/.gitconfig, and .git/hooks/.
- Excludes modifications made by the Git process itself to reduce false positives.
- Uses EVAL to tag potential persistence events and counts occurrences to identify unusual activity.
- Monitors processes started by Git hooks to detect suspicious activity related to Git configurations.
- OSQuery query is provided to retrieve detailed file information related to Git configurations and hooks.
## MITRE ATT&CK Techniques

- [T1546.004](https://attack.mitre.org/techniques/T1546/004)
- [T1059.004](https://attack.mitre.org/techniques/T1059/004)

## License

- `Elastic License v2`

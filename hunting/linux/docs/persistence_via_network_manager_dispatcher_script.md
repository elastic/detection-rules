# Persistence via NetworkManager Dispatcher Script

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies potential persistence mechanisms leveraging NetworkManager Dispatcher scripts on Linux systems. NetworkManager Dispatcher scripts are executed automatically when the network state changes, making them an interesting target for attackers seeking to persist or execute malicious actions during network transitions. This hunt monitors suspicious activity involving the creation or modification of dispatcher scripts, tracks processes spawned by `nm-dispatcher` or scripts in `/etc/NetworkManager/dispatcher.d/`, and retrieves metadata for files in these directories for deeper analysis. The approach enables analysts to identify and respond to NetworkManager dispatcher script persistence techniques.

- **UUID:** `8f3bf096-2f3b-4d38-9925-0eb120323da3`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL, SQL]`
- **Source File:** [Persistence via NetworkManager Dispatcher Script](../queries/persistence_via_network_manager_dispatcher_script.toml)

## Query

```sql
sql
from logs-endpoint.events.process-*
| keep @timestamp, host.os.type, event.type, event.action, process.parent.executable, process.parent.name, process.command_line, process.executable, agent.id
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.parent.executable like "/etc/NetworkManager/dispatcher.d/*" or process.parent.name == "nm-dispatcher"
)
| stats cc = count(), agent_count = count_distinct(agent.id) by process.command_line, process.executable, process.parent.executable
| where agent_count <= 3 and cc < 15
| sort cc asc
| limit 100
```

```sql
sql
from logs-endpoint.events.file-*
| keep @timestamp, host.os.type, event.type, event.action, file.path, file.extension, process.name, process.executable, agent.id
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.type in ("creation", "change") and file.path like "/etc/NetworkManager/dispatcher.d/*"
 and not (
  file.extension in ("swp", "dpkg-new") or
  process.name in ("dnf", "yum", "dpkg")
)
| stats cc = count(), agent_count = count_distinct(agent.id) by file.path, process.executable
| where agent_count <= 3
| sort cc asc
| limit 100
```

```sql
sql
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
WHERE f.path LIKE '/etc/NetworkManager/dispatcher.d/%'
AND (mtime > strftime('%s', 'now') - (7 * 86400)); -- Modified in the last 7 days
```

## Notes

- Monitors processes executed by `nm-dispatcher` or scripts located in `/etc/NetworkManager/dispatcher.d/`, identifying unauthorized or anomalous executions.
- Tracks file creations and modifications within the `/etc/NetworkManager/dispatcher.d/` directory to detect potential tampering or malicious additions.
- Retrieves metadata for NetworkManager Dispatcher scripts, including ownership, access times, and modification timestamps, to highlight unauthorized changes or suspicious file attributes.
- Focuses on recent changes to dispatcher scripts within the last 7 days to ensure timely detection of potential persistence mechanisms.

## MITRE ATT&CK Techniques

- [T1546](https://attack.mitre.org/techniques/T1546)

## License

- `Elastic License v2`

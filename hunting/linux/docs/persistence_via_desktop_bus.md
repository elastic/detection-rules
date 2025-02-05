# Persistence via Desktop Bus (D-Bus)

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies potential persistence mechanisms leveraging the Desktop Bus (D-Bus) system on Linux. D-Bus is an inter-process communication (IPC) system that facilitates communication between various system components and applications. Attackers can exploit D-Bus by creating or modifying services, configuration files, or system policies to maintain persistence or execute unauthorized actions. This hunt monitors suspicious process activity related to D-Bus, tracks changes to key D-Bus configuration and service files, and retrieves metadata for further analysis. The approach helps analysts identify and respond to persistence techniques targeting D-Bus.

- **UUID:** `2223bbda-b931-4f33-aeb4-0e0732a370dd`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL, SQL]`
- **Source File:** [Persistence via Desktop Bus (D-Bus)](../queries/persistence_via_desktop_bus.toml)

## Query

```sql
sql
from logs-endpoint.events.process-*
| keep @timestamp, host.os.type, event.type, event.action, process.name, process.parent.name, process.command_line, process.executable, process.parent.executable, agent.id
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.parent.name == "dbus-daemon" or process.name == "dbus-send"
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
| where host.os.type == "linux" and event.type in ("creation", "change") and (
  file.path like "/usr/share/dbus-1/*" or
  file.path like "/usr/local/share/dbus-1/*" or
  file.path like "/etc/dbus-1/*" or
  file.path like "/home/*/.local/share/dbus-1/*"
) and not (
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
WHERE (
        f.path LIKE '/usr/share/dbus-1/system-services/%'
        OR f.path LIKE '/usr/local/share/dbus-1/system-services/%'
        OR f.path LIKE '/etc/dbus-1/system.d/%'
        OR f.path LIKE '/usr/share/dbus-1/system.d/%'
        OR f.path LIKE '/usr/share/dbus-1/session-services/%'
        OR f.path LIKE '/home/%/.local/share/dbus-1/services/%'
        OR f.path LIKE '/etc/dbus-1/session.d/%'
        OR f.path LIKE '/usr/share/dbus-1/session.d/%'
      )
AND (mtime > strftime('%s', 'now') - (7 * 86400)); -- Modified in the last 7 days
```

## Notes

- Monitors processes related to D-Bus, such as `dbus-daemon` and `dbus-send`, to identify unauthorized or anomalous executions indicative of persistence or abuse.
- Tracks creations and modifications to critical D-Bus directories, including `/usr/share/dbus-1/`, `/usr/local/share/dbus-1/`, `/etc/dbus-1/`, and `~/.local/share/dbus-1/`, which may indicate malicious activity.
- Retrieves metadata for D-Bus service and configuration files, such as file ownership, access times, and modification timestamps, to detect unauthorized changes.
- Focuses on recent changes within the last 7 days to identify timely indicators of compromise while maintaining historical context for analysis.

## MITRE ATT&CK Techniques

- [T1543](https://attack.mitre.org/techniques/T1543)

## License

- `Elastic License v2`

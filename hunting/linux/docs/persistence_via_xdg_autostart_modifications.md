# XDG Persistence

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies potential persistence mechanisms via modifications to XDG autostart directories on Linux systems. XDG Autostart entries can be used to execute arbitrary commands or scripts when a user logs in. It monitors file creation or modification events in system-wide, user-specific, and root-specific autostart directories. Additionally, it monitors processes started by common Linux desktop session managers to detect suspicious activity related to autostart entries.

- **UUID:** `8dcc2161-65e0-4448-a03a-1c4e0cbc9330`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL, SQL]`
- **Source File:** [XDG Persistence](../queries/persistence_via_xdg_autostart_modifications.toml)

## Query

```sql
from logs-endpoint.events.file-*
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.type in ("creation", "change") and (

    // System-wide autostart directories
    file.path like "/etc/xdg/autostart/*" or
    file.path like "/usr/share/autostart/*" or

    // User-specific autostart directories
    file.path like "/home/*/.config/autostart/*" or
    file.path like "/home/*/.local/share/autostart/*" or
    file.path like "/home/*/.config/autostart-scripts/*" or

    // Root-specific autostart directories
    file.path like "/root/.config/autostart/*" or
    file.path like "/root/.local/share/autostart/*" or
    file.path like "/root/.config/autostart-scripts/*"
) and not (
    process.name in (
      "dpkg", "dockerd", "yum", "dnf", "snapd", "pacman", "pamac-daemon", "microdnf", "podman", "apk"
    ) or
    process.executable == "/proc/self/exe" or
    process.executable like "/dev/fd/*" or
    file.extension in ("dpkg-remove", "swx", "swp")
)
| eval persistence = case(
    // System-wide autostart directories
    file.path like "/etc/xdg/autostart/*" or
    file.path like "/usr/share/autostart/*" or

    // User-specific autostart directories
    file.path like "/home/*/.config/autostart/*" or
    file.path like "/home/*/.local/share/autostart/*" or
    file.path like "/home/*/.config/autostart-scripts/*" or

    // Root-specific autostart directories
    file.path like "/root/.config/autostart/*" or
    file.path like "/root/.local/share/autostart/*" or
    file.path like "/root/.config/autostart-scripts/*",
    process.name,
    null
)
| stats pers_count = count(persistence) by process.executable, file.path
| where pers_count > 0 and pers_count <= 20
| sort pers_count asc
| limit 100
```

```sql
from logs-endpoint.events.process-*
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.parent.name in (
  "plasmashell", "gnome-session", "xfce4-session", "gnome-session-binary", "mate-session", "cinnamon-session",
  "lxsession", "lxqt-session", "unity-session", "pantheon-session", "enlightenment_start"
)
| stats cc = count(*) by process.command_line, process.parent.executable
| where cc <= 20
| sort cc asc
| limit 100
```

```sql
SELECT name, path, source, status, type FROM startup_items
WHERE type == "Startup Item" AND status == "enabled" AND (
    source LIKE "/etc/xdg/autostart/%"
    OR source LIKE "/usr/share/autostart/%"
    OR source LIKE "/home/%/.config/autostart/%"
    OR source LIKE "/home/%/.local/share/autostart/%"
    OR source LIKE "/home/%/.config/autostart-scripts/%"
    OR source LIKE "/root/.config/autostart/%"
    OR source LIKE "/root/.local/share/autostart/%"
    OR source LIKE "/root/.config/autostart-scripts/%"
)
```

```sql
SELECT
    f.filename,
    f.path,
    u.username AS file_owner,
    g.groupname AS group_owner,
    datetime(f.atime, 'unixepoch') AS file_last_access_time,
    datetime(f.mtime, 'unixepoch') AS file_last_modified_time,
    datetime(f.ctime, 'unixepoch') AS file_last_status change_time,
    datetime(f.btime, 'unixepoch') AS file_created_time,
    f.size AS size_bytes
FROM
    file f
LEFT JOIN
    users u ON f.uid = u.uid
LEFT JOIN
    groups g ON f.gid = g.gid
WHERE
    f.path LIKE "/etc/xdg/autostart/%"
    OR f.path LIKE "/usr/share/autostart/%"
    OR f.path LIKE "/home/%/.config/autostart/%"
    OR f.path LIKE "/home/%/.local/share/autostart/%"
    OR f.path LIKE "/home/%/.config/autostart-scripts/%"
    OR f.path LIKE "/root/.config/autostart/%"
    OR f.path LIKE "/root/.local/share/autostart/%"
    OR f.path LIKE "/root/.config/autostart-scripts/%"
```

## Notes

- Monitors for file creation or modification events in system-wide, user-specific, and root-specific XDG autostart directories.
- Excludes modifications made by expected update processes such as package managers to reduce false positives.
- Uses EVAL to tag potential persistence events and counts occurrences to identify unusual activity.
- Monitors processes started by common Linux desktop session managers to detect suspicious activity related to autostart entries.
- OSQuery queries are provided to retrieve enabled XDG startup items and detailed file information related to autostart directories.

## MITRE ATT&CK Techniques

- [T1547.001](https://attack.mitre.org/techniques/T1547/001)
- [T1053.005](https://attack.mitre.org/techniques/T1053/005)

## License

- `Elastic License v2`

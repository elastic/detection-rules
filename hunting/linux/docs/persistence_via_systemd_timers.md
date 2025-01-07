# Persistence via Systemd (Timers)

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies potential persistence mechanisms via systemd (timers) on Linux systems. It monitors for file creation or modification events related to systemd service and timer configurations, as well as generators, which can indicate attempts to establish persistence through scheduled tasks.

- **UUID:** `d2d24ad6-a315-4e05-a3f9-e205eb805df4`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL, SQL]`
- **Source File:** [Persistence via Systemd (Timers)](../queries/persistence_via_systemd_timers.toml)

## Query

```sql
from logs-endpoint.events.file-*
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.type in ("creation", "change") and (

    // System-wide/user-specific services/timers (root permissions required)
    file.path like "/run/systemd/system/*" or
    file.path like "/etc/systemd/system/*" or
    file.path like "/etc/systemd/user/*" or
    file.path like "/usr/local/lib/systemd/system/*" or
    file.path like "/lib/systemd/system/*" or
    file.path like "/usr/lib/systemd/system/*" or
    file.path like "/usr/lib/systemd/user/*" or

    // user-specific services/timers (user permissions required)
    file.path like "/home/*/.config/systemd/user/*" or
    file.path like "/home/*/.local/share/systemd/user/*" or

    // System-wide generators (root permissions required)
    file.path like "/etc/systemd/system-generators/*" or
    file.path like "/usr/local/lib/systemd/system-generators/*" or
    file.path like "/lib/systemd/system-generators/*" or
    file.path like "/etc/systemd/user-generators/*" or
    file.path like "/usr/local/lib/systemd/user-generators/*" or
    file.path like "/usr/lib/systemd/user-generators/*"

) and not (
    process.name in (
      "dpkg", "dockerd", "yum", "dnf", "snapd", "pacman", "pamac-daemon",
      "netplan", "systemd", "generate"
    ) or
    process.executable == "/proc/self/exe" or
    process.executable like "/dev/fd/*" or
    file.extension in ("dpkg-remove", "swx", "swp")
)
| eval persistence = case(

    // System-wide/user-specific services/timers (root permissions required)
    file.path like "/run/systemd/system/*" or
    file.path like "/etc/systemd/system/*" or
    file.path like "/etc/systemd/user/*" or
    file.path like "/usr/local/lib/systemd/system/*" or
    file.path like "/lib/systemd/system/*" or
    file.path like "/usr/lib/systemd/system/*" or
    file.path like "/usr/lib/systemd/user/*" or

    // user-specific services/timers (user permissions required)
    file.path like "/home/*/.config/systemd/user/*" or
    file.path like "/home/*/.local/share/systemd/user/*" or

    // System-wide generators (root permissions required)
    file.path like "/etc/systemd/system-generators/*" or
    file.path like "/usr/local/lib/systemd/system-generators/*" or
    file.path like "/lib/systemd/system-generators/*" or
    file.path like "/etc/systemd/user-generators/*" or
    file.path like "/usr/local/lib/systemd/user-generators/*" or
    file.path like "/usr/lib/systemd/user-generators/*",
    process.name,
    null
)
| stats pers_count = count(persistence) by process.executable, file.path
| where pers_count > 0 and pers_count <= 20
| sort pers_count asc
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
    (f.path LIKE "/run/systemd/system/%"
    OR f.path LIKE "/etc/systemd/system/%"
    OR f.path LIKE "/etc/systemd/user/%"
    OR f.path LIKE "/usr/local/lib/systemd/system/%"
    OR f.path LIKE "/lib/systemd/system/%"
    OR f.path LIKE "/usr/lib/systemd/system/%"
    OR f.path LIKE "/usr/lib/systemd/user/%"
    OR f.path LIKE "/home/%/.config/systemd/user/%"
    OR f.path LIKE "/home/%/.local/share/systemd/user/%")
    AND f.filename LIKE "%.service"
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
    f.directory IN (
        '/run/systemd/system',
        '/etc/systemd/system',
        '/etc/systemd/user',
        '/usr/local/lib/systemd/system',
        '/lib/systemd/system',
        '/usr/lib/systemd/system',
        '/usr/lib/systemd/user',
        '/home/.config/systemd/user',
        '/home/.local/share/systemd/user'
    )
    AND f.filename LIKE "%.timer"
ORDER BY
    f.mtime DESC;
```

```sql
SELECT
    f.filename,
    f.path,
    u.username AS file_owner,
    g.groupname AS group_owner,
    datetime(f.atime, 'unixepoch') AS file_last_access_time,
    datetime(f.mtime, 'unixepoch') AS file_last modified_time,
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
    f.directory IN (
        '/etc/systemd/system-generators/',
        '/usr/local/lib/systemd/system-generators/',
        '/lib/systemd/system-generators/',
        '/etc/systemd/user-generators/',
        '/usr/local/lib/systemd/user-generators/',
        '/usr/lib/systemd/user-generators/'
    )
ORDER BY
    f.mtime DESC;
```

```sql
SELECT name, path, source, status, type FROM startup_items
WHERE type == "systemd unit" AND status == "active" AND
name LIKE "%.service" OR name LIKE  "%.timer"
```

## Notes

- This hunt includes multiple ES|QL and OSQuery queries to identify potential persistence mechanisms via systemd timers on Linux systems.
- Detects file creation or modification events in directories and files associated with systemd services, timers, and generators, such as /run/systemd/system, /etc/systemd/system, /etc/systemd/user, and various /usr/lib/systemd directories.
- Excludes common legitimate processes and file types to minimize false positives.
- Uses EVAL to tag potential persistence events and counts occurrences to identify unusual activity.
- OSQuery queries are provided to complement the detection by retrieving detailed file information and entries related to systemd services, timers, and generators.

## MITRE ATT&CK Techniques

- [T1053.005](https://attack.mitre.org/techniques/T1053/005)
- [T1546.002](https://attack.mitre.org/techniques/T1546/002)

## License

- `Elastic License v2`

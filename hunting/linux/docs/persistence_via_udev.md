# Persistence via Udev

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies potential persistence mechanisms via Udev rules on Linux systems. Udev is a device manager for the Linux kernel that manages device nodes in /dev. Udev is responsible for creating and removing device nodes in /dev when devices are added or removed from the system. Udev executes scripts when devices are added or removed from the system. This query monitors file creation or modification events in Udev rule directories and processes started by Udevadm. These activities can indicate attempts to establish persistence through Udev configurations. The hunt lists detailed information for further analysis and investigation.

- **UUID:** `8d42a644-5b60-4165-a8f1-84d5bcdd4ade`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL, SQL]`
- **Source File:** [Persistence via Udev](../queries/persistence_via_udev.toml)

## Query

```sql
from logs-endpoint.events.file-*
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.type in ("creation", "change") and (
    file.path like "/etc/udev/rules.d/*" or
    file.path like "/run/udev/rules.d/*" or
    file.path like "/usr/lib/udev/rules.d/*" or
    file.path like "/usr/local/lib/udev/rules.d/*" or
    file.path like "/lib/udev/*"
) and not process.name in (
  "dpkg", "dockerd", "yum", "dnf", "snapd", "pacman", "pamac-daemon",
  "microdnf", "podman", "apk", "netplan", "generate"
)
| eval persistence = case(
    file.path like "/etc/udev/rules.d/*" or
    file.path like "/run/udev/rules.d/*" or
    file.path like "/usr/lib/udev/rules.d/*" or
    file.path like "/usr/local/lib/udev/rules.d/*" or
    file.path like "/lib/udev/*",
    process.name,
    null
)
| stats pers_count = count(persistence) by process.executable, file.path
| where pers_count > 0 and pers_count <= 20
| sort pers_count asc
```

```sql
from logs-endpoint.events.process-*
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.action == "exec" and event.type == "start" and process.parent.name == "udevadm" and
// Excluding these because this is typical udev behavior.
// If you suspect Udev persistence, remove this exclusion in order to do a more elaborate search
not (process.executable like "/lib/*" or process.executable like "/usr/lib/*")
| stats cc = count(), host_count = count_distinct(host.name) by process.executable
// Tweak the process/host count if you suspect Udev persistence
| where host_count <= 5 and cc < 50
| sort cc asc
| limit 100
```

```sql
SELECT
    f.filename,
    f.path,
    u.username AS file_owner,
    g.groupname AS group owner,
    datetime(f.atime, 'unixepoch') AS file_last_access_time,
    datetime(f.mtime, 'unixepoch') AS file_last_modified_time,
    datetime(f.ctime, 'unixepoch') AS file_last_status_change_time,
    datetime(f.btime, 'unixepoch') AS file_created_time,
    f.size AS size bytes,
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
        '/etc/udev/rules.d/',
        '/run/udev/rules.d/',
        '/usr/lib/udev/rules.d/',
        '/usr/local/lib/udev/rules.d/',
        '/lib/udev/'
    )
ORDER BY
    f.mtime DESC;
```

## Notes

- Monitors for file creation or modification events in Udev rule directories such as /etc/udev/rules.d/, /run/udev/rules.d/, /usr/lib/udev/rules.d/, and /lib/udev/.
- Excludes modifications made by expected update processes such as package managers to reduce false positives.
- Uses EVAL to tag potential persistence events and counts occurrences to identify unusual activity.
- Monitors processes started by Udevadm to detect suspicious activity related to Udev rules.
- OSQuery query is provided to retrieve detailed file information related to Udev rules.

## MITRE ATT&CK Techniques

- [T1547.010](https://attack.mitre.org/techniques/T1547/010)

## License

- `Elastic License v2`

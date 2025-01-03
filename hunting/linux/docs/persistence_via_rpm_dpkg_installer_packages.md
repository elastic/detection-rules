# Persistence via DPKG/RPM Package

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies potential persistence mechanisms leveraging DPKG or RPM package managers on Linux systems. These tools, used for installing and managing software, can be exploited by attackers to execute malicious scripts or establish persistence via lifecycle scripts (preinst, postinst, prerm, postrm). This hunt focuses on detecting suspicious file creations and anomalous process activity related to these package managers.

- **UUID:** `1d7cae97-2dea-4f01-b04c-85fa4bd991d0`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL, SQL]`
- **Source File:** [Persistence via DPKG/RPM Package](../queries/persistence_via_rpm_dpkg_installer_packages.toml)

## Query

```sql
from logs-endpoint.events.file-*
| keep @timestamp, host.os.type, event.action, file.path, file.name, agent.id, process.executable
| where @timestamp > now() - 7 days
| where host.os.type == "linux" and event.action in ("rename", "creation") and (
  file.path like "/var/lib/dpkg/info/*" or
  file.path like "/var/lib/rpm/*"
) and not (
  // Remove these exclusions if you have a high suspicion of this activity
  // Add additional exclusions here if necessary based on your environment
  file.name like "*-new" or
  file.name like "__db*.*" or
  file.name like "*.list" or
  file.name like "*.md5sums*"
)
| stats cc = count(), agent_count = count_distinct(agent.id) by file.name, process.executable
| where agent_count <= 3
| sort cc asc
| limit 100
```

```sql
from logs-endpoint.events.process-*
| keep @timestamp, host.os.type, event.type, event.action, process.parent.command_line, process.parent.executable, agent.id, process.executable, process.command_line
| where @timestamp > now() - 7 days
| where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.parent.command_line like "*/var/tmp/rpm-tmp.*" or
  process.parent.executable like "/var/lib/dpkg/info/*"
)
| stats cc = count(), agent_count = count_distinct(agent.id) by process.executable, process.command_line
| where agent_count <= 3
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
WHERE (
        f.path LIKE '/var/lib/dpkg/info/%'
        OR f.path LIKE '/var/lib/rpm/%'
      )
AND (mtime > strftime('%s', 'now') - (7 * 86400)); -- Modified in the last 7 days
```

## Notes

- Monitors for the creation or renaming of files in directories associated with DPKG and RPM package managers, such as /var/lib/dpkg/info/ and /var/lib/rpm/.
- Excludes common benign file patterns (e.g., temporary files, checksum files, or list files) to reduce noise while detecting unusual modifications.
- Analyzes processes executed from lifecycle scripts or directories associated with package managers, such as /var/tmp/rpm-tmp.* and /var/lib/dpkg/info/*.
- Uses OSQuery queries to gather detailed metadata on files and directories modified by package management activities for forensic analysis.
- Provides counts and statistics to help highlight rare or unusual package management-related activity.

## MITRE ATT&CK Techniques

- [T1546.016](https://attack.mitre.org/techniques/T1546/016)

## License

- `Elastic License v2`

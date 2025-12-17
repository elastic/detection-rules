# Persistence via PolicyKit

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies potential persistence mechanisms leveraging PolicyKit (Polkit) on Linux systems. PolicyKit is a system service used to manage system-wide privileges and is often targeted by attackers to escalate privileges or maintain persistence. By monitoring file creations and modifications in key PolicyKit directories and analyzing metadata for Polkit-related files, this hunt helps detect unauthorized changes or suspicious activities that may indicate malicious use of PolicyKit. It provides detailed insights into potentially compromised PolicyKit configurations, enabling analysts to identify and respond to this persistence technique.

- **UUID:** `4e8a17d3-9139-4b45-86d5-79e8d1eba71e`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL, SQL]`
- **Source File:** [Persistence via PolicyKit](../queries/persistence_via_policykit.toml)

## Query

```sql
sql
from logs-endpoint.events.file-*
| keep @timestamp, host.os.type, event.type, event.action, file.path, file.extension, process.name, process.executable, agent.id
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.type in ("creation", "change") and (
  file.path like "/etc/polkit-1/rules.d/*" or
  file.path like "/usr/share/polkit-1/rules.d/*" or
  file.path like "/usr/share/polkit-1/actions/*" or
  file.path like "/etc/polkit-1/localauthority/*" or
  file.path like "/var/lib/polkit-1/localauthority/*"
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
        f.path = '/etc/polkit-1/rules.d/%'
        OR f.path LIKE '/usr/share/polkit-1/rules.d/%'
        OR f.path LIKE '/usr/share/polkit-1/actions/%'
        OR f.path LIKE '/etc/polkit-1/localauthority/%%'
        OR f.path LIKE '/var/lib/polkit-1/localauthority/%%'
      )
AND (mtime > strftime('%s', 'now') - (7 * 86400)); -- Modified in the last 7 days
```

## Notes

- Tracks file creations and modifications in PolicyKit-related directories such as `/etc/polkit-1/rules.d/`, `/usr/share/polkit-1/rules.d/`, `/usr/share/polkit-1/actions/`, and others to detect unauthorized additions or tampering.
- Retrieves metadata for PolicyKit configuration files, including ownership, last access times, and modification timestamps, to identify unauthorized or suspicious changes.
- Focuses on recent file modifications within the last 7 days to provide timely detection of potential malicious activities.
- Helps detect rare or anomalous file modifications by correlating process execution with file activities, enabling analysts to identify subtle signs of compromise.

## MITRE ATT&CK Techniques

- [T1543](https://attack.mitre.org/techniques/T1543)

## License

- `Elastic License v2`

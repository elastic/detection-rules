# Persistence via Packager Manager

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies potential persistence mechanisms via package manager configurations on Linux systems. It monitors file creation or modification events in directories related to APT, YUM, and DNF package managers. Additionally, it monitors processes started by these package managers. These activities can indicate attempts to establish persistence through package manager configurations. The hunt lists detailed information for further analysis and investigation.

- **UUID:** `e2a2d9b9-0123-4e2e-a92e-be890ab80f23`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL, SQL]`

## Query

```sql
from logs-endpoint.events.file-*
| where @timestamp > now() - 90 day
| where host.os.type == "linux" and event.type in ("creation", "change") and (
    file.path like "/etc/apt/apt.conf.d/*" or
    file.path like "/usr/lib/python*/site-packages/dnf-plugins/*" or
    file.path like "/etc/dnf/plugins/*" or
    file.path like "/usr/lib/yum-plugins/*" or
    file.path like "/etc/yum/pluginconf.d/*"
) and not process.name in (
  "dpkg", "dockerd", "yum", "dnf", "snapd", "pacman", "pamac-daemon",
  "microdnf", "podman", "apk", "yumBackend.py"
)
| eval persistence = case(
    file.path like "/etc/apt/apt.conf.d/*" or
    file.path like "/usr/lib/python*/site-packages/dnf-plugins/*" or
    file.path like "/etc/dnf/plugins/*" or
    file.path like "/usr/lib/yum-plugins/*" or
    file.path like "/etc/yum/pluginconf.d/*",
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
| where host.os.type == "linux" and event.action == "exec" and event.type == "start" and process.parent.name in ("apt", "yum", "dnf")
| stats process_cli_count = count(process.command_line), process_count = count(process.executable), host_count = count_distinct(host.name) by process.executable
| where host_count <= 5 and process_count < 50
| sort process_cli_count asc
| limit 100
```

```sql
SELECT
    f.filename,
    f.path,
    u.username AS file_owner,
    g.groupname AS group owner,
    datetime(f.atime, 'unixepoch') AS file_last_access time,
    datetime(f.mtime, 'unixepoch') AS file last_modified time,
    datetime(f.ctime, 'unixepoch') AS file last_status change time,
    datetime(f.btime, 'unixepoch') AS file created time,
    f.size AS size bytes
FROM
    file f
LEFT JOIN
    users u ON f.uid = u.uid
LEFT JOIN
    groups g ON f.gid = g.gid
WHERE
    f.path LIKE '/etc/apt/apt.conf.d/%'
    OR f.path LIKE '/usr/lib/python%/site-packages/dnf-plugins/%'
    OR f.path LIKE '/etc/dnf/plugins/%'
    OR f.path LIKE '/usr/lib/yum-plugins/%'
    OR f.path LIKE '/etc/yum/pluginconf.d/%'
```

```sql
SELECT * FROM apt_sources
```

```sql
SELECT * FROM yum_sources
```

## Notes

- Monitors for file creation or modification events in directories related to APT, YUM, and DNF package managers such as /etc/apt/apt.conf.d/, /etc/dnf/plugins/, /usr/lib/yum-plugins/, and others.
- Excludes modifications made by expected update processes such as package managers to reduce false positives.
- Uses EVAL to tag potential persistence events and counts occurrences to identify unusual activity.
- Monitors processes started by package managers to detect suspicious activity related to package manager configurations.
- OSQuery queries are provided to retrieve detailed file information related to package manager configurations, as well as sources for APT and YUM.
## MITRE ATT&CK Techniques

- [T1546.004](https://attack.mitre.org/techniques/T1546/004)
- [T1059.004](https://attack.mitre.org/techniques/T1059/004)

## License

- `Elastic License v2`

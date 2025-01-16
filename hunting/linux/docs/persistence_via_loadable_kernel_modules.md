# Persistence via Loadable Kernel Modules

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies potential persistence mechanisms leveraging Loadable Kernel Modules (LKMs) on Linux systems. LKMs enable dynamic extension of kernel functionality but can be abused by attackers to load malicious code into the kernel, granting them high privileges or persistence. This hunt monitors suspicious kernel module file creations, LKM-related process executions, and access to kernel module configuration files.

- **UUID:** `d667d328-fadc-4a52-9b46-f42b1a83181c`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL, SQL]`
- **Source File:** [Persistence via Loadable Kernel Modules](../queries/persistence_via_loadable_kernel_modules.toml)

## Query

```sql
from logs-endpoint.events.file-*
| keep @timestamp, host.os.type, event.type, event.action, file.extension, file.path, process.executable, agent.id
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.type == "creation" and file.extension == "ko" and not (
  // Add your exclusions here
  file.path like "/run/initramfs/*" or
  file.path like "/var/tmp/mkinitramfs*"
)
| stats cc = count(), agent_count = count_distinct(agent.id) by file.path, process.executable
| where agent_count <= 3
| sort cc asc
| limit 100
```

```sql
from logs-endpoint.events.process-*
| keep @timestamp, host.os.type, event.type, event.action, process.name, agent.id, process.args, process.args_count
| where @timestamp > now() - 30 days
| where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.name in ("kmod", "modprobe", "insmod", "rmmod")
| stats cc = count(), agent_count = count_distinct(agent.id) by process.args, process.args_count
| where cc == 1 and agent_count == 1 and process.args_count <= 3
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
    datetime(f.ctime, 'unixepoch') AS file_last_status_change_time
    datetime(f.btime, 'unixepoch') AS file_created_time,
    f.size AS size_bytes
FROM
    file f
LEFT JOIN
    users u ON f.uid = u.uid
LEFT JOIN
    groups g ON f.gid = g.gid
WHERE
    f.path LIKE '/etc/modprobe.d/%'
    OR f.path LIKE '/usr/lib/modprobe.d/%'
    OR f.path LIKE '/usr/lib/security/%'
    OR f.path LIKE '/etc/modules-load.d/%'
    OR f.path LIKE '/run/modules-load.d/%'
    OR f.path LIKE '/usr/local/lib/modules-load.d/%'
    OR f.path like '/usr/lib/modules-load.d/%'
    OR f.path = '/etc/modules'
```

```sql
SELECT * FROM kernel_modules;
```

## Notes

- Tracks the creation of loadable kernel module files (.ko) in non-standard directories to identify potential malicious modules.
- Monitors the execution of processes related to kernel module management, such as kmod, modprobe, insmod, and rmmod, to detect suspicious or unusual activity.
- Identifies changes to critical kernel module configuration files, including /etc/modprobe.d/, /etc/modules, and related paths.
- Uses OSQuery queries to gather detailed metadata on kernel modules currently loaded, supporting forensic analysis of potential persistence mechanisms.
- Provides statistics and counts to help identify rare or anomalous kernel module-related events.

## MITRE ATT&CK Techniques

- [T1547.006](https://attack.mitre.org/techniques/T1547/006)

## License

- `Elastic License v2`

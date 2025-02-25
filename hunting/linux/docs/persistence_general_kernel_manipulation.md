# General Kernel Manipulation

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt focuses on detecting general kernel and bootloader manipulations on Linux systems, which are critical for system integrity and security. Attackers may target kernel components, bootloader configurations, or secure boot settings to establish persistence or compromise the system at a low level. By monitoring changes to `/boot/` files, examining kernel and platform information, and detecting processes spawned by `systemd`, this hunt provides visibility into potential kernel and boot-related threats. The combination of ES|QL and OSQuery queries ensures robust detection and hunting capabilities for kernel manipulation and persistence attempts.

- **UUID:** `9997c6fb-4e01-477f-9011-fc7fc6b000b6`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL, SQL]`
- **Source File:** [General Kernel Manipulation](../queries/persistence_general_kernel_manipulation.toml)

## Query

```sql
sql
from logs-endpoint.events.file-*
| keep @timestamp, host.os.type, event.type, event.action, file.path, file.extension, process.executable, agent.id
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.type in ("creation", "change") and file.path like "/boot/*" and
not file.extension in ("dpkg-new", "swp")
| stats cc = count(), agent_count = count_distinct(agent.id) by file.path, process.executable
| where agent_count <= 3 and cc <= 5
| sort cc asc
| limit 100
```

```sql
sql
from logs-endpoint.events.process-*
| keep @timestamp, host.os.type, event.type, event.action, process.parent.name, process.executable, process.command_line, process.parent.executable, agent.id
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.type == "info" and event.action == "already_running" and process.parent.name == "systemd"
| stats cc = count(), agent_count = count_distinct(agent.id) by process.executable, process.command_line
| where agent_count <= 3 and cc < 25
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
WHERE f.path LIKE '/boot/%'
AND (mtime > strftime('%s', 'now') - (7 * 86400)); -- Modified in the last 7 days
```

```sql
sql
SELECT * FROM kernel_info;
```

```sql
sql
SELECT * FROM secureboot;
```

```sql
sql
SELECT * FROM platform_info;
```

```sql
sql
SELECT * FROM kernel_keys;
```

## Notes

- Tracks file creations and modifications within the `/boot/` directory to identify potential tampering with kernel or bootloader files, such as the kernel image, GRUB configuration, or Initramfs.
- Monitors processes spawned by `systemd` with the `already_running` action to detect unusual behavior linked to kernel manipulations.
- Retrieves metadata for kernel and boot-related files, including file ownership, last access times, and modification timestamps, to identify unauthorized changes.
- Leverages OSQuery tables like `kernel_info`, `secureboot`, `platform_info`, and `kernel_keys` to gain insights into the system's boot and kernel integrity, ensuring comprehensive coverage of kernel manipulation activities.
- Helps identify rare or anomalous events by providing statistics on processes and file activities, enabling analysts to detect subtle signs of compromise or persistence.

## MITRE ATT&CK Techniques

- [T1542](https://attack.mitre.org/techniques/T1542)

## License

- `Elastic License v2`

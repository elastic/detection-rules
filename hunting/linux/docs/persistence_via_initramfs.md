# Persistence via Initramfs

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies potential persistence mechanisms leveraging modifications to Initramfs (initial RAM filesystem) on Linux systems. Initramfs is a key component in the boot process, providing early user-space initialization before the main filesystem is mounted. Attackers can abuse Initramfs by injecting malicious scripts, modules, or files into its configuration, allowing them to gain persistence or execute malicious code during system boot. This hunt monitors file creations and modifications within Initramfs-related directories, tracks executions of Initramfs manipulation tools, and retrieves metadata for critical Initramfs-related files for forensic analysis.

- **UUID:** `1206f5e2-aee6-4e5c-bda0-718fe440b1cf`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL, SQL]`
- **Source File:** [Persistence via Initramfs](../queries/persistence_via_initramfs.toml)

## Query

```sql
sql
from logs-endpoint.events.file-*
| keep @timestamp, host.os.type, event.type, event.action, file.path, file.extension, process.executable, agent.id
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.type == "creation" and (
  file.path like "/lib/dracut/modules.d/*" or
  file.path like "/usr/lib/dracut/modules.d/*"
) and not file.extension in ("swp", "dpkg-new")
| stats cc = count(), agent_count = count_distinct(agent.id) by file.path, process.executable
| where agent_count <= 3
| sort cc asc
| limit 100
```

```sql
sql
from logs-endpoint.events.process-*
| keep @timestamp, host.os.type, event.type, event.action, process.name, process.executable, process.parent.executable, agent.id
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.name in ("unmkinitramfs", "dracut", "binwalk")
| stats cc = count(), agent_count = count_distinct(agent.id) by process.executable, process.parent.executable
| where agent_count <= 3 and cc < 10
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
        f.path = '/lib/dracut/modules.d/%'
        OR f.path LIKE '/usr/lib/dracut/modules.d/%'
        OR f.path LIKE '/boot/initrd.img%'
      )
AND (mtime > strftime('%s', 'now') - (7 * 86400)); -- Modified in the last 7 days
```

## Notes

- Tracks file creations within directories used by Dracut to manage Initramfs such as /lib/dracut/modules.d/ and /usr/lib/dracut/modules.d/, focusing on unusual additions or unauthorized changes.
- Monitors the execution of processes used to manipulate Initramfs, including tools like dracut, unmkinitramfs, and binwalk, which could indicate attempts to extract, analyze, or modify the Initramfs.
- Queries metadata for Initramfs-related files, such as those in /boot/initrd.img, to identify recent modifications or anomalous attributes like ownership changes or unexpected access times.
- Helps detect unauthorized persistence mechanisms that leverage modifications to Initramfs, improving detection coverage for threats targeting the early stages of the Linux boot process.

## MITRE ATT&CK Techniques

- [T1542](https://attack.mitre.org/techniques/T1542)

## License

- `Elastic License v2`

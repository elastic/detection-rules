# Persistence via Dynamic Linker Hijacking

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies potential persistence mechanisms via dynamic linker hijacking on Linux systems. Attackers can manipulate environment variables like LD_PRELOAD and LD_LIBRARY_PATH to execute malicious shared libraries, hijacking the dynamic linker process for persistence or privilege escalation. This hunt monitors for suspicious usage of these environment variables, the creation of shared library files (.so), and access to critical dynamic linker configuration files.

- **UUID:** `664d65ec-029e-4746-bf97-7bf3a0113e6a`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL, SQL]`
- **Source File:** [Persistence via Dynamic Linker Hijacking](../queries/persistence_via_dynamic_linker_hijacking.toml)

## Query

```sql
from logs-endpoint.events.process-*
| keep @timestamp, host.os.type, event.type, event.action, process.env_vars, agent.id
| where @timestamp > now() - 30 days
| where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.env_vars like "LD_PRELOAD=*.so" or
process.env_vars like "LD_LIBRARY_PATH=*"
| stats env_count = count(process.env_vars) by agent.id, process.env_vars
```

```sql
from logs-endpoint.events.file-*
| keep @timestamp, host.os.type, event.type, event.action, file.extension, file.path, process.executable, agent.id
| where @timestamp > now() - 30 days
| where host.os.type == "linux" and event.type == "creation" and file.extension == "so" and not (
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
SELECT * FROM process_envs
WHERE key = "LD_PRELOAD"
OR key = "LD_LIBRARY_PATH";
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
    f.path = "/etc/ld.so.preload"
    OR f.path = "/etc/ld.so.conf"
    OR f.path = "/etc/ld.so.cache"
    OR f.path LIKE "/etc/ld.so.conf.d/%";
```

```sql
SELECT 
    p.pid,
    p.name AS process_name,
    p.path AS process_path,
    p.cmdline AS command_line,
    pe.key AS env_key,
    pe.value AS env_value,
    (strftime('%s', 'now') - p.start_time) AS runtime_seconds
FROM 
    processes p
JOIN 
    process_envs pe ON p.pid = pe.pid
WHERE 
    pe.key IN ('LD_PRELOAD', 'LD_LIBRARY_PATH')
    AND (strftime('%s', 'now') - p.start_time) > 3600;
```

## Notes

- Identifies processes with suspicious environment variables, specifically LD_PRELOAD and LD_LIBRARY_PATH, which are often used in dynamic linker hijacking attacks.
- Monitors the creation of shared object (.so) files in non-standard or uncommon directories to detect potential malicious libraries.
- Tracks modifications to critical dynamic linker files like /etc/ld.so.preload, /etc/ld.so.conf, and related directories, which are common targets for attackers.
- Uses process environment variables and metadata to detect running processes that rely on suspicious linker configurations, focusing on processes that persist longer than typical short-lived tasks.
- Provides complementary OSQuery queries for detailed file metadata, including file ownership and timestamps, to support forensic investigations.
- This hunt leverages the process.env_vars field, which is a field that must be manually enabled within the Elastic Defend policy advanced settings tab.

## MITRE ATT&CK Techniques

- [T1574.006](https://attack.mitre.org/techniques/T1574/006)

## License

- `Elastic License v2`

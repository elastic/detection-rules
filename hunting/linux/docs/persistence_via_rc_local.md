# Persistence via rc.local/rc.common

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies potential persistence mechanisms via rc.local and rc.common on Linux systems. RC scripts are used to start custom applications, services, scripts or commands during start-up. RC scripts have mostly been replaced by Systemd. However, through the "systemd-rc-local-generator", these files can be converted to services that run at boot. The query monitors for file creation or modification events in the /etc/rc.local and /etc/rc.common files, as well as processes started by these scripts. These activities can indicate attempts to establish persistence through rc.local modifications.

- **UUID:** `a95f778f-2193-4a3d-bbbe-7b02d5740638`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [system](https://docs.elastic.co/integrations/system)
- **Language:** `[ES|QL, SQL]`
- **Source File:** [Persistence via rc.local/rc.common](../queries/persistence_via_rc_local.toml)

## Query

```sql
from logs-endpoint.events.file-*
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.type in ("creation", "change") and (file.path == "/etc/rc.local" or file.path == "/etc/rc.common")
| eval persistence = case(file.path == "/etc/rc.local" or file.path == "/etc/rc.common", process.name, null)
| stats pers_count = count(persistence), agent_count = count_distinct(agent.id) by process.executable
| where pers_count > 0 and pers_count <= 3 and agent_count <= 3
| sort pers_count asc
| limit 100
```

```sql
from logs-system.syslog-*
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and process.name in ("rc.local", "rc.common")
| stats cc = count(), host_count = count_distinct(host.name) by message
| where host_count <= 3 and cc < 10
| sort cc asc
| limit 100
```

```sql
SELECT * FROM systemd_units WHERE id = "rc-local.service"
```

```sql
SELECT * FROM startup_items WHERE name = "rc-local.service"
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
    f.path in ('/etc/rc.local', '/etc/rc.common')
```

## Notes

- This hunt includes multiple ES|QL and OSQuery queries to detect potential persistence mechanisms via rc.local on Linux systems.
- Detects file creation or modification events in the /etc/rc.local and /etc/rc.common files, which are used for system initialization scripts.
- Uses EVAL to tag potential persistence events and counts occurrences to identify unusual activity.
- Monitors processes started by rc.local and rc.common scripts to detect potential persistence mechanisms.
- Syslog hunting query is provided to complement the detection by analyzing syslog entries related to rc.local and rc.common processes.
- OSQuery queries are provided to retrieve systemd unit states, startup items, and detailed file information related to rc.local and rc.common.

## MITRE ATT&CK Techniques

- [T1037.004](https://attack.mitre.org/techniques/T1037/004)
- [T1546.003](https://attack.mitre.org/techniques/T1546/003)

## License

- `Elastic License v2`

# Persistence via SSH Configurations and/or Keys

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies potential SSH persistence mechanisms on Linux systems using OSQuery. It monitors SSH keys, authorized_keys files, SSH configuration files, and SSH file information to detect unauthorized access or persistence techniques. The hunt lists detailed information for further analysis and investigation.

- **UUID:** `aa759db0-4499-42f2-9f2f-be3e00fdebfa`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[SQL]`
- **Source File:** [Persistence via SSH Configurations and/or Keys](../queries/persistence_via_ssh_configurations_and_keys.toml)

## Query

```sql
SELECT * FROM user_ssh_keys
```

```sql
SELECT authorized_keys.*
FROM users
JOIN authorized_keys
USING(uid)
```

```sql
SELECT * FROM ssh_configs
```

```sql
SELECT
    f.filename,
    f.path,
    u.username AS file_owner,
    g.groupname AS group_owner,
    datetime(f.atime, 'unixepoch') AS file_last_access_time,
    datetime(f.mtime, 'unixepoch') AS file_last_modified_time,
    datetime(f.ctime, 'unixepoch') AS file_last_status change_time,
    datetime(f.btime, 'unixepoch') AS file_created_time,
    f.size AS size_bytes
FROM
    file f
LEFT JOIN
    users u ON f.uid = u.uid
LEFT JOIN
    groups g ON f.gid = g.gid
WHERE
    f.path LIKE "/root/.ssh/%"
    OR f.path LIKE "/home/%/.ssh/%"
    OR f.path LIKE "/etc/ssh/%"
    OR f.path LIKE "/etc/ssh/sshd_config.d/%"
    OR f.path LIKE "/etc/ssh/ssh_config.d/%"
```

## Notes

- Monitors SSH keys, authorized_keys files, and SSH configuration files using OSQuery to detect potential unauthorized access or persistence techniques.
- Lists detailed information about SSH files, including paths, owners, and permissions.
- Requires additional data analysis and investigation into results to identify malicious or unauthorized SSH configurations and keys.

## MITRE ATT&CK Techniques

- [T1098.004](https://attack.mitre.org/techniques/T1098/004)
- [T1563.001](https://attack.mitre.org/techniques/T1563/001)

## License

- `Elastic License v2`

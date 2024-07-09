# OSQuery SUID Hunting

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies SUID binaries on Linux systems using OSQuery. SUID binaries can be exploited by attackers to gain elevated privileges. The hunt includes queries to list all SUID binaries and detailed information about these files, focusing on regular files owned by root with SUID or SGID bits set.

- **UUID:** `2db642d2-621a-4183-88b5-b2659dc2c940`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[SQL]`
- **Source File:** [OSQuery SUID Hunting](../queries/privilege_escalation_via_suid_binaries.toml)

## Query

```sql
SELECT * FROM suid_bin
```

```sql
SELECT
    f.filename,
    f.path,
    f.mode,
    f.uid,
    f.gid,
    f.type,
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
f.type == "regular" AND
(f.uid == 0 or f.gid == 0) AND
(f.mode LIKE "2%" OR f.mode LIKE "4%") AND
(
  f.path LIKE "/%%" OR
  f.path LIKE "/%%/%%" OR
  f.path LIKE "/%%/%%/%%" OR
  f.path LIKE "/%%/%%/%%/%%"
)
```

## Notes

- Identifies SUID binaries using OSQuery to detect potentially exploitable files with SUID or SGID bits set.
- Lists all SUID binaries and provides detailed information about these files, including their paths, owners, and permissions.
- Focuses on regular files owned by root with SUID or SGID bits set to identify potential privilege escalation vectors.
- OSQuery has limited support for wildcard queries, therefore the query includes multiple LIKE conditions for directories. These can be increased and decreased, based on the environment

## MITRE ATT&CK Techniques

- [T1548.001](https://attack.mitre.org/techniques/T1548/001)
- [T1574.002](https://attack.mitre.org/techniques/T1574/002)

## License

- `Elastic License v2`

# Persistence Through Reverse/Bind Shells

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt provides several OSQuery queries that can aid in the detection of reverse/bind shells. Reverse shells are a type of shell in which the target machine communicates back to the attacking machine. Bind shells are a type of shell in which the target machine opens a communication port on the victim machine and waits for an attacker to connect to it. These shells can be used by attackers to gain remote access to a system.

- **UUID:** `7422faf1-ba51-49c3-b8ba-13759e6bcec4`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[SQL]`
- **Source File:** [Persistence Through Reverse/Bind Shells](../queries/persistence_reverse_bind_shells.toml)

## Query

```sql
SELECT (
  CASE family 
  WHEN 2 THEN 'IP4' 
  WHEN 10 THEN 'IP6' 
  ELSE family END
) AS family, (
  CASE protocol 
  WHEN 6 THEN 'TCP' 
  WHEN 17 THEN 'UDP' 
  ELSE protocol END
) AS protocol, local_address, local_port, 
  remote_address, remote_port 
FROM process_open_sockets 
WHERE family IN (2, 10) 
AND protocol IN (6, 17) 
```

```sql
SELECT cmdline, name, path, pid, state, threads, total_size 
FROM processes 
WHERE cmdline != ''
```

```sql
SELECT pid, address, port, socket, protocol, path FROM listening_ports
```

## Notes

- The hunt provides OSQuery queries to detect reverse/bind shells on Linux systems.
- The first hunt query retrieves information about open sockets on the system.
- The second hunt query retrieves information about running processes on the system.
- The third hunt query retrieves information about listening ports on the system.
- Investigate strange or unexpected open sockets, processes, or listening ports on the system.
- Use the information from each hunt to pivot and investigate further for potential reverse/bind shells.

## MITRE ATT&CK Techniques

- [T1059.004](https://attack.mitre.org/techniques/T1059/004)

## License

- `Elastic License v2`

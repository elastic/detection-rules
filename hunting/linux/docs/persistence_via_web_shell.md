# Persistence via Web Shell

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies potential persistence mechanisms leveraging web shells on Linux systems. Web shells are malicious scripts or executables that attackers deploy to provide remote access, execute arbitrary commands, or maintain persistence on compromised systems. This hunt focuses on detecting suspicious file creation events and anomalous network activity associated with known web shell behaviors.

- **UUID:** `e2e4a1ad-5e03-4968-927c-9ef13c49a3b8`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL]`
- **Source File:** [Persistence via Web Shell](../queries/persistence_via_web_shell.toml)

## Query

```sql
from logs-endpoint.events.file-*
| keep @timestamp, host.os.type, event.action, file.extension, process.name, agent.id, file.name, process.executable
| where @timestamp > now() - 30 days
| where host.os.type == "linux" and event.action in ("rename", "creation") and
file.extension in ("php", "py", "pl", "rb", "rs", "lua", "jsp") and not (
  // Add your noisy exclusions here
  process.name in ("dnf", "dpkg", "pip3", "pip", "yum", "tar", "code", "vmtoolsd")
)
| stats cc = count(), agent_count = count_distinct(agent.id) by file.name, process.executable
| where agent_count <= 3
| sort cc asc
| limit 100
```

```sql
from logs-endpoint.events.network-*
| keep @timestamp, host.os.type, event.type, event.action, process.name, source.ip, agent.id, process.executable, process.command_line
| where @timestamp > now() - 30 days
| where host.os.type == "linux" and event.type == "end" and event.action == "disconnect_received" and
(
  process.name like "ruby*" or
  process.name like "perl*" or
  process.name like "python*" or
  process.name like "php*"
) and source.ip IS NOT null and not CIDR_MATCH(source.ip, "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "::1", "172.18.0.0/16")
| stats cc = count(), agent_count = count_distinct(agent.id) by process.executable, process.command_line, source.ip
| where agent_count <= 3
| sort cc asc
| limit 100
```

## Notes

- Monitors for the creation or renaming of files with extensions commonly associated with web shells, such as PHP, Python, Perl, Ruby, Lua, and JSP scripts.
- Analyzes network disconnect events to identify anomalous connections initiated by scripting engines, indicating potential use of web shells for remote access.
- Provides statistics and counts to detect rare or unusual activity related to file modifications or network events, helping prioritize investigation efforts.

## MITRE ATT&CK Techniques

- [T1505.003](https://attack.mitre.org/techniques/T1505/003)

## License

- `Elastic License v2`

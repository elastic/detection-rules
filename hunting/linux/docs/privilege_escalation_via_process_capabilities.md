# Process Capability Hunting

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies processes on Linux systems with specific capabilities set. It monitors process execution events where processes have effective or permitted capabilities, which can be indicative of elevated privileges. The hunt focuses on non-root users to detect potential privilege escalation attempts. The hunt lists detailed information for further analysis and investigation.

- **UUID:** `6f67704d-e5b1-4613-912c-e2965660fe17`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL]`
- **Source File:** [Process Capability Hunting](../queries/privilege_escalation_via_process_capabilities.toml)

## Query

```sql
from logs-endpoint.events.process-*
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.action == "exec" and event.type == "start" and (process.thread.capabilities.effective is not null or process.thread.capabilities.permitted is not null) and user.id != "0" and
not (
  // Remove these if you expect persistence through capabilities
  process.executable like "/var/lib/docker/*" or
  process.name == "gnome-keyring-daemon" or
  process.thread.capabilities.permitted == "CAP_WAKE_ALARM"
)
| stats cc = count(), host_count = count_distinct(host.name) by process.executable, process.thread.capabilities.effective, process.thread.capabilities.permitted
| where host_count <= 3 and cc < 5
| sort cc asc
| limit 100
```

```sql
from logs-endpoint.events.process-*
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and event.action == "exec" and event.type == "start" and (
  process.thread.capabilities.effective in ("CAP_SYS_MODULE", "CAP_SYS_PTRACE", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_SETUID", "CAP_SETGID", "CAP_SYS_ADMIN") or
  process.thread.capabilities.permitted in ("CAP_SYS_MODULE", "CAP_SYS_PTRACE", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_SETUID", "CAP_SETGID", "CAP_SYS_ADMIN")
) and user.id != "0"
| stats cc = count(), host_count = count_distinct(host.name) by process.executable, process.thread.capabilities.effective, process.thread.capabilities.permitted
| where host_count <= 3 and cc < 5
| sort cc asc
| limit 100
```

## Notes

- Monitors process execution events where processes have specific capabilities set, such as CAP_SYS_MODULE, CAP_SYS_PTRACE, and others.
- Excludes certain processes and capabilities to reduce false positives, but these can be adjusted based on your environment.
- Uses EVAL to tag potential privilege escalation events and counts occurrences to identify unusual activity.
- Focuses on non-root users to detect potential privilege escalation attempts.
- Requires additional data analysis and investigation into results to identify malicious or unauthorized use of process capabilities.

## MITRE ATT&CK Techniques

- [T1548.001](https://attack.mitre.org/techniques/T1548/001)
- [T1548.003](https://attack.mitre.org/techniques/T1548/003)

## License

- `Elastic License v2`

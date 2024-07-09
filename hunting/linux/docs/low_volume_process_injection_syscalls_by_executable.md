# Low Volume Process Injection-Related Syscalls by Process Executable

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies low volume process injection-related syscalls on Linux systems. It monitors audit logs for syscalls related to process injection, such as ptrace and memfd_create. The hunt focuses on processes that make these syscalls infrequently, which can indicate potential malicious activity.

- **UUID:** `c9931736-d5ec-4c89-b4d2-d71dcf5ca12a`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL]`
- **Source File:** [Low Volume Process Injection-Related Syscalls by Process Executable](../queries/low_volume_process_injection_syscalls_by_executable.toml)

## Query

```sql
from logs-auditd_manager.auditd-*, logs-auditd.log-*, auditbeat-*
| where @timestamp > now() - 30 day
| where host.os.type == "linux" and auditd.data.syscall in ("ptrace", "memfd_create")
| stats cc = count(*) by process.executable, auditd.data.syscall
| where cc <= 10
| limit 100
| sort cc asc
```

## Notes

- Monitors for process injection-related syscalls such as ptrace and memfd_create.
- Counts the occurrences of these syscalls by process executable to identify processes that make these syscalls infrequently.
- Focuses on low volume occurrences to detect potential malicious activity related to process injection.

## MITRE ATT&CK Techniques

- [T1055.001](https://attack.mitre.org/techniques/T1055/001)
- [T1055.009](https://attack.mitre.org/techniques/T1055/009)

## License

- `Elastic License v2`

# Segmentation Fault & Potential Buffer Overflow Hunting

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies segmentation faults (segfaults) and potential buffer overflow attacks on Linux systems by parsing syslog messages related to segfaults. It captures details about the crashing process, shared object file, and other relevant information to help identify and investigate potential exploitation attempts.

- **UUID:** `3f3fd2b9-940c-4310-adb1-d8b7d726e281`
- **Integration:** [system](https://docs.elastic.co/integrations/system)
- **Language:** `[ES|QL]`

## Query

```sql
from logs-system.syslog*
| where @timestamp > now() - 12 hour
| where host.os.type == "linux" and process.name == "kernel" and message like "*segfault*"
| grok message "\\[%{NUMBER:timestamp}\\] %{WORD:process}\\[%{NUMBER:pid}\\]: segfault at %{BASE16NUM:segfault_address} ip %{BASE16NUM:instruction_pointer} sp %{BASE16NUM:stack_pointer} error %{NUMBER:error_code} in %{DATA:so_file}\\[%{BASE16NUM:so_base_address}\\+%{BASE16NUM:so_offset}\\]"
| keep timestamp, process, pid, so_file, segfault_address, instruction_pointer, stack_pointer, error_code, so_base_address, so_offset
```

```sql
from logs-system.syslog*
| where host.os.type == "linux" and process.name == "kernel" and message like "*segfault*"
| where @timestamp > now() - 12 hour
| grok message "\\[%{DATA:timestamp}\\] %{WORD:process}\\[%{NUMBER:pid}\\]: segfault at %{BASE16NUM:segfault_address} ip %{BASE16NUM:instruction_pointer} sp %{BASE16NUM:stack_pointer} error %{NUMBER:error_code} in %{DATA:so_name}\\[%{BASE16NUM:so_base_address}\\+%{BASE16NUM:so_offset}\\] likely on CPU %{NUMBER:cpu} \\(core %{NUMBER:core}, socket %{NUMBER:socket}\\)"
| eval timestamp = REPLACE(timestamp, "\\s+", "")
| keep timestamp, process, pid, segfault_address, instruction_pointer, stack_pointer, error_code, so_name, so_base_address, so_offset, cpu, core, socket
| stats cc = count() by process, so_name
// Alter this threshold to make sense for your environment
| where cc > 100
| limit 10
```

## Notes

- Detects segfaults and parses syslog messages related to segfaults to identify the crashing process and shared object file along with additional crash details.
- Uses GROK to extract relevant fields from syslog messages.
- Counts occurrences of segfaults within a plain text message field to potentially detect buffer overflow attacks and unsuccessful process injection attempts.
- Removes prepending spaces from syslog messages using EVAL to ensure consistent parsing.
- Depending on the Syslog configuration, additional parsing may be required to extract the necessary fields from the message.
## MITRE ATT&CK Techniques

- [T1203](https://attack.mitre.org/techniques/T1203)
- [T1068](https://attack.mitre.org/techniques/T1068)

## License

- `Elastic License v2`

# Unusual File Downloads from Source Addresses

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies unusual file download activities on Linux systems. It detects instances where commonly used download utilities such as curl and wget are executed with command lines that contain IP addresses, which can indicate potentially suspicious file downloads.

- **UUID:** `0d061fad-cf35-43a6-b9b7-986c348bf182`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL]`

## Query

```sql
from logs-endpoint.events.process-*
| where @timestamp > now() - 7 day
| where host.os.type == "linux" and event.type == "start" and process.name in ("curl", "wget") and process.command_line rlike """.*[0-9]{1,3}(\.[0-9]{1,3}){3}.*"""
| stats process_cli_count = count(process.command_line), host_count = count(host.name) by process.command_line, process.executable, host.name
| where process_cli_count <= 10 and host_count <= 5
| sort process_cli_count asc
| limit 100
```

## Notes

- Detects instances where download utilities like curl and wget are used with IP addresses in their command lines.
- Monitors for potentially suspicious file downloads, which are often seen in malicious activities.
- Uses process command line counting in conjunction with host counting to minimize false positives caused by legitimate downloads.
- The process command line count threshold is set to <= 10, and the host count threshold is set to <= 5 to balance detection and noise.
## MITRE ATT&CK Techniques

- [T1071.001](https://attack.mitre.org/techniques/T1071/001)
- [T1071.004](https://attack.mitre.org/techniques/T1071/004)

## License

- `Elastic License v2`

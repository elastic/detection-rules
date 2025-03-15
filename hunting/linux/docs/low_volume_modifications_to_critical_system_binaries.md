# Low Volume Modifications to Critical System Binaries by Unique Host

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies low volume modifications to critical system binaries on Linux systems. It monitors file modification events in critical directories such as /bin, /usr/bin, /sbin, and /usr/sbin. The hunt focuses on modifications made by unique hosts, excluding expected update processes like package managers. This can help detect unauthorized or suspicious modifications to system binaries.

- **UUID:** `c7044817-d9a5-4755-abab-9059e50dab24`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL]`
- **Source File:** [Low Volume Modifications to Critical System Binaries by Unique Host](../queries/low_volume_modifications_to_critical_system_binaries.toml)

## Query

```sql
from logs-endpoint.events.file-*
| where @timestamp > now() - 7 day
| where host.os.type == "linux" and
  (file.path like "/bin/*" or file.path like "/usr/bin/*" or file.path like "/sbin/*" or file.path like "/usr/sbin/*") and
  not (

  // Exclude expected update processes, e.g., package managers
  process.executable in ("/usr/bin/apt", "/usr/bin/dpkg", "/usr/bin/yum", "/usr/bin/rpm", "/usr/bin/pacman",
  "/usr/bin/pamac-daemon", "/usr/bin/update-alternatives", "/usr/bin/dockerd", "/usr/bin/microdnf", "/sbin/apk") or

  // Exclude certain benign or expected modification patterns, if applicable
  file.path like "/usr/bin/gzip*" // Example exclusion, adjust based on your environment
)
| stats modification_count = count(file.path), unique_files_modified = count_distinct(file.path), host_count = count_distinct(host.name) by process.executable
| where modification_count >= 1 and host_count == 1
| sort modification_count asc
| limit 100
```

## Notes

- Monitors for file modifications in critical directories like /bin, /usr/bin, /sbin, and /usr/sbin.
- Excludes modifications made by expected update processes such as package managers to reduce false positives.
- Counts the number of unique files modified by each host and the number of modifications made.
- Focuses on modifications made by unique hosts to detect unauthorized or suspicious changes.

## MITRE ATT&CK Techniques

- [T1070.004](https://attack.mitre.org/techniques/T1070/004)
- [T1569.002](https://attack.mitre.org/techniques/T1569/002)

## License

- `Elastic License v2`

# DNS Queries via LOLBins with Low Occurence Frequency

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt looks for DNS queries performed by commonly abused Microsoft binaries that perform remote file transfer or binary proxy execution. Aggregations for the number of occurrences is limited to one host to reduce the number of potentially legitimate hits.

- **UUID:** `ebf8eb13-c98a-4d2c-8bdb-3f72a3a3961b`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [windows](https://docs.elastic.co/integrations/windows)
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.network-*, logs-windows.sysmon_operational-*
| where @timestamp > now() - 7 day and host.os.family == "windows" and event.category == "network" and
  event.action in ("lookup_requested", "DNSEvent (DNS query)") and
  process.name in ("powershell.exe", "rundll32.exe", "certutil.exe", "curl.exe", "wget.exe", "CertReq.exe", "bitsadmin.exe", "mshta.exe", "pwsh.exe", "wmic.exe", "wscript.exe", "cscript.exe", "msbuild.exe", "regsvr32.exe", "MSBuild.exe", "InstallUtil.exe", "RegAsm.exe", "RegSvcs.exe",  "msxsl.exe", "CONTROL.EXE", "Microsoft.Workflow.Compiler.exe", "msiexec.exe") and dns.question.name rlike """.+\.[a-z-A-Z]{2,3}"""
| keep process.name,  dns.question.name, host.id
| stats occurrences = count(*), hosts = count_distinct(host.id) by process.name, dns.question.name
| where hosts == 1
```

## Notes

- Utilities like curl and SSL verification for web services are noisy, while others are rare such as scripting utilities and are worth further investigation.
- Connection to legit domains like Github, Discord, Telegram and many other legit web services by LOLBins is still suspicious and require further investigation.
## MITRE ATT&CK Techniques

- [T1071](https://attack.mitre.org/techniques/T1071)

## License

- `Elastic License v2`

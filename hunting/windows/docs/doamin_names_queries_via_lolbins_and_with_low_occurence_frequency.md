# Doamin Names queries via Lolbins and with low occurence frequency

---

## Metadata

- **Author:** Elastic
- **UUID:** `ebf8eb13-c98a-4d2c-8bdb-3f72a3a3961b`
- **Integration:** `logs-endpoint.events.network-*, logs-windows.sysmon_operational-*`
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

- Utilities like curl and SSL verification web-servvices are noisy, while others are rare like scripting utilities and are worth further investigation.
- Connection to legit domains like github, discord, telegram and many other legit web-services by lolbins is still suspicious and require further investigation.
## MITRE ATT&CK Techniques

- [T1071](https://attack.mitre.org/techniques/T1071)

## License

- `Elastic License v2`

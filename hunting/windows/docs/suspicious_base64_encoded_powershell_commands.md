# Suspicious Base64 Encoded Powershell Command

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies base64 encoded powershell commands in process start events and filters ones with suspicious keywords like downloaders and evasion related commands.

- **UUID:** `2e583d3c-7ad6-4544-a0db-c685b2066493`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [windows](https://docs.elastic.co/integrations/windows), [system](https://docs.elastic.co/integrations/system)
- **Language:** `[ES|QL]`
- **Source File:** [Suspicious Base64 Encoded Powershell Command](../queries/suspicious_base64_encoded_powershell_commands.toml)

## Query

```sql
from logs-endpoint.events.process-*, logs-windows.sysmon_operational-*, logs-system.security-*
| where host.os.type == "windows" and event.category == "process" and event.type == "start" and TO_LOWER(process.name) == "powershell.exe" and process.command_line rlike ".+ -(e|E).*"
| keep agent.id, process.command_line
 /* simplified regex to extract base64 encoded blob */
| grok process.command_line """(?<base64_data>([A-Za-z0-9+/]+={1,2}$|[A-Za-z0-9+/]{100,}))"""
| where base64_data is not null
 /* base64 decode added in 8.14 */
| eval decoded_base64_cmdline = replace(TO_LOWER(FROM_BASE64(base64_data)), """\u0000""", "")
 /* most common suspicious keywords, you can add more patterns here */
| where decoded_base64_cmdline rlike """.*(http|webclient|download|mppreference|sockets|bxor|.replace|reflection|assembly|load|bits|start-proc|iwr|frombase64).*"""
| keep agent.id, process.command_line, decoded_base64_cmdline
```

## Notes

- This hunt can be expanded to include more evasion techniques and downloaders.
- Pivoting by `agent.id` can provide more context on the affected hosts.

## MITRE ATT&CK Techniques

- [T1059](https://attack.mitre.org/techniques/T1059)
- [T1059.001](https://attack.mitre.org/techniques/T1059/001)
- [T1027](https://attack.mitre.org/techniques/T1027)
- [T1027.010](https://attack.mitre.org/techniques/T1027/010)

## License

- `Elastic License v2`

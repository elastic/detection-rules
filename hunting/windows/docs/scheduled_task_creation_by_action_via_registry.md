# Scheduled tasks Creation by Action via Registry

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt looks for scheduled tasks creation by action using registry events. Scheduled tasks actions are saved under the TaskCache registry key in base64 encoded blob. Malware often abuse LOLBins to proxy execution or run executables from unusual paths, you can add more patterns to the query.

- **UUID:** `df50f65e-e820-47f4-a039-671611582f51`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL]`
- **Source File:** [Scheduled tasks Creation by Action via Registry](../queries/scheduled_task_creation_by_action_via_registry.toml)

## Query

```sql
from logs-endpoint.events.registry-*
| where  @timestamp > now() - 7 day
| where host.os.type == "windows" and event.category == "registry" and event.action == "modification" and
  registry.path like """HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\*Actions*"""
 /* scheduled task actions are saved under the TaskCache registry key in base64 encoded blob */
| eval scheduled_task_action = replace(TO_LOWER(FROM_BASE64(registry.data.bytes)), """\u0000""", "")
 /* commonly abused lolbin set to run as a scheduled task */
| where scheduled_task_action rlike """.*(users\\public\\|\\appdata\\roaming|programdata|powershell.exe|rundll32.exe|regsvr32.exe|mshta.exe|cscript.exe|wscript.exe|cmd.exe|forfiles|msiexec.exe|wmic.exe|msbuild.exe|http|cmstp.exe|msxsl.exe|ie4uinit.exe).*""" and not scheduled_task_action like "localsystem*"
| keep scheduled_task_action, registry.path, agent.id
| stats count_agents = count_distinct(agent.id) by scheduled_task_action
 /* helps reduce result to instances limited to one agent */
| where count_agents == 1
```

## Notes

- Malware often abuse LOLBins to proxy execution or run executables from unusual paths, you can add more patterns to the query.

## MITRE ATT&CK Techniques

- [T1053](https://attack.mitre.org/techniques/T1053)
- [T1053.005](https://attack.mitre.org/techniques/T1053/005)

## License

- `Elastic License v2`

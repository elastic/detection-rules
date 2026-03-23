# Do Shell Script Execution via Apple Events

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies `do shell script` execution via AppleScript using macOS Unified Logs Apple Event telemetry. The Apple Event type `syso,exec` corresponds to the `do shell script` command, which allows AppleScript to execute arbitrary shell commands. While `do shell script` has many legitimate uses, it is heavily abused by macOS stealers to run shell commands for reconnaissance, credential theft, data exfiltration, and payload execution. This hunt returns hosts and event counts for `syso,exec` Apple Events, enabling analysts to identify unusual volumes of shell execution via AppleScript.

- **UUID:** `447987db-4501-416b-b3b3-9176871a6b20`
- **Integration:** [unified_logs](https://docs.elastic.co/integrations/unified_logs)
- **Language:** `[ES|QL]`
- **Source File:** [Do Shell Script Execution via Apple Events](../queries/execution_do_shell_script_via_apple_events.toml)

## Query

```sql
FROM logs-unified_logs.log-*
| WHERE @timestamp > NOW() - 7 day
| WHERE host.os.type == "macos" AND event.dataset == "unified_logs.log" AND message LIKE "*syso,exec*"
| STATS event_count = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY host.name
| WHERE event_count >= 3
| SORT event_count DESC
```

## Notes

- This hunt returns hosts with `syso,exec` Apple Events aggregated by host and count, sorted by highest count.
- A high volume of `do shell script` executions from a single host may indicate automated malicious activity or stealer malware running shell commands in bulk.
- Pivot by `host.name` and review the `message` field contents to understand what shell commands are being executed.
- Correlate with other Apple Event types (`syso,dlog`, `Jons,gClp`, `syso,ntoc`) on the same host to identify potential stealer activity chains.
- If private data is enabled in Unified Logs, the `message` field may contain the actual shell command being executed, providing additional triage context.

## MITRE ATT&CK Techniques

- [T1059.002](https://attack.mitre.org/techniques/T1059/002)

## References

- https://pberba.github.io/security/2026/02/21/aemonitor/
- https://www.elastic.co/docs/reference/integrations/unifiedlogs

## License

- `Elastic License v2`

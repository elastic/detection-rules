# ADRecon Directory Report Collection

---

## Metadata

- **Author:** Elastic
- **Description:** Finds PowerShell processes creating CSV report names associated with ADRecon and groups the events by host and process.
The output directory can be customized, so the query does not require the default ADRecon-Report directory name.
These file names are triage leads that also occur during authorized directory inventory and security assessments.

- **UUID:** `391a01ba-8a8e-4619-a574-29d7ff707684`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[ES|QL]`
- **Source File:** [ADRecon Directory Report Collection](../queries/discovery_adrecon_report_collection.toml)

## Query

```sql
FROM logs-endpoint.events.file-*
| WHERE @timestamp > NOW() - 7 day
| WHERE host.os.type == "windows" AND event.category == "file" AND event.type == "creation" AND
    TO_LOWER(process.name) IN ("powershell.exe", "pwsh.exe")
| EVAL report_path = TO_LOWER(file.path)
| WHERE ENDS_WITH(report_path, "\\csv-files\\users.csv") OR
    ENDS_WITH(report_path, "\\csv-files\\computerspns.csv") OR
    ENDS_WITH(report_path, "\\csv-files\\aboutadrecon.csv")
| KEEP @timestamp, host.id, host.name, process.entity_id, process.name, user.name, file.path
| STATS report_events = COUNT(*), report_paths = VALUES(file.path),
    first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.id, host.name, process.entity_id, process.name, user.name
| SORT report_events DESC
| LIMIT 100
```

## Notes

- This hunt and its guidance were created with the assistance of generative AI and reviewed. Validate the query and adapt the guidance to your environment.
- Requires Elastic Defend file-creation events. Adjust the seven-day lookback and result limit to the investigation window and check for truncated results.
- ADRecon supports a custom OutputDir. The query accepts any output root but still depends on the CSV-Files subdirectory and the listed report names. Renamed reports, other output formats and alternative PowerShell hosts are outside its scope.
- One report is sufficient for a hunt result. Multiple report paths from the same process provide additional context; common names such as Users.csv are not unique to ADRecon. The result count is file events, not distinct executions or proof of malicious activity.
- Inspect the report paths and contents, process tree, command line, user and available PowerShell script-block logs. Correlate directory-query activity and other reports by host.id and process.entity_id. Confirm whether directory inventory or a security assessment was authorized.
- A matching path does not prove successful collection of directory data. If the activity is unauthorized, preserve the script, reports and process evidence and investigate subsequent access or use through the established response process.

## MITRE ATT&CK Techniques

- [T1087](https://attack.mitre.org/techniques/T1087)
- [T1087.002](https://attack.mitre.org/techniques/T1087/002)

## References

- https://github.com/adrecon/ADRecon
- https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1087.002/T1087.002.md

## License

- `Elastic License v2`

# Privilege Escalation Identification via Existing Sudoers File

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies entries in the sudoers file on Linux systems using OSQuery. The sudoers file controls which users have administrative privileges and can be a target for attackers seeking to escalate their privileges. This hunt lists all sudoers rules for further analysis.

- **UUID:** `a7a7d5x5-6789-4a7a-a57a-be456ab80b78`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[SQL]`

## Query

```sql
SELECT * FROM sudoers
```

## Notes

- Lists all entries in the sudoers file using OSQuery to detect potentially unauthorized or suspicious rules.
- Requires additional data analysis and investigation into results to identify malicious or misconfigured sudoers entries.
- Focuses on monitoring and analyzing administrative privileges granted through the sudoers file.
## MITRE ATT&CK Techniques

- [T1548.003](https://attack.mitre.org/techniques/T1548/003)

## License

- `Elastic License v2`

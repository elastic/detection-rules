# Sensitive File Access via Docker

---

## Metadata

- **Author:** Elastic
- **Description:** Detects Docker or Docker Desktop processes accessing potentially sensitive host files, including SSH keys, cloud provider credentials, browser data, or crypto wallet files. This behavior may indicate container escape attempts, data harvesting from the host, or misconfigured volume mounts exposing secrets.

- **UUID:** `fb136106-207c-11f0-aa05-f661ea17fbcd`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[EQL]`
- **Source File:** [Sensitive File Access via Docker](../queries/execution_suspicious_file_access_via_docker.toml)

## Query

```sql
file where event.action == "open" and
  (process.name in ("docker", "Docker Desktop") or process.name like "com.docker*") and
  not file.name in ("System.keychain", "login.keychain-db")
```

## Notes

- Docker processes accessing sensitive host files may suggest attempts to harvest credentials from the host system.
- You may enrich this detection by adding file paths for `.aws/credentials`, `.ssh/id_rsa`, `keychain`, or `Cookies`.
- Consider filtering legitimate developer use cases or adjusting for specific containers if needed.

## MITRE ATT&CK Techniques

- [T1083](https://attack.mitre.org/techniques/T1083)
- [T1552.001](https://attack.mitre.org/techniques/T1552/001)

## References

- https://www.elastic.co/security-labs/dprk-code-of-conduct
- https://unit42.paloaltonetworks.com/slow-pisces-new-custom-malware/
- https://slowmist.medium.com/cryptocurrency-apt-intelligence-unveiling-lazarus-groups-intrusion-techniques-a1a6efda7d34
- https://x.com/safe/status/1897663514975649938
- https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/

## License

- `Elastic License v2`

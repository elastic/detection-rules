# Self-Deleted Python Script Outbound Network Connection

---

## Metadata

- **Author:** Elastic
- **Description:** Detects an outbound network connection by a Python script that was executed and deleted from disk. A recent DPRK 
initial access campaign used a Python script that self 
deletes and continues operating in memory.
- **UUID:** `04d4b300-bf2f-4e86-8fab-c51502a1db32`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint)
- **Language:** `[EQL]`
- **Source File:** [Self-Deleted Python Script Outbound Network Connection](../queries/defense_evasion_self_deleted_python_script_outbound_network_connection.toml)

## Query

```sql
sequence by process.entity_id with maxspan=10s
[file where event.action == "deletion" and file.extension in ("py", "pyc") and process.name like~ "python*"] 
[network where event.type == "start" and
   not cidrmatch(destination.ip, 
       "240.0.0.0/4", "233.252.0.0/24", "224.0.0.0/4", "198.19.0.0/16", "192.18.0.0/15", 
       "192.0.0.0/24", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", 
       "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", 
       "100.64.0.0/10", "192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
       "::1", "FE80::/10", "FF00::/8")]
```

## Notes

- This hunt identifies a deleted Python script followed immediately followed by external network activity from the same process.
- Outbound connection filtering avoids internal IPs and infrastructure — can be tuned to your network space.

## MITRE ATT&CK Techniques

- [T1059.006](https://attack.mitre.org/techniques/T1059/006)
- [T1105](https://attack.mitre.org/techniques/T1105)
- [T1070.004](https://attack.mitre.org/techniques/T1070/004)

## References

- https://www.elastic.co/security-labs/dprk-code-of-conduct
- https://unit42.paloaltonetworks.com/slow-pisces-new-custom-malware/
- https://slowmist.medium.com/cryptocurrency-apt-intelligence-unveiling-lazarus-groups-intrusion-techniques-a1a6efda7d34
- https://x.com/safe/status/1897663514975649938
- https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/

## License

- `Elastic License v2`

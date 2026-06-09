# Mythic C2 TLS Certificate Observed in Cisco SD-WAN Exploitation

---

## Metadata

- **Author:** Elastic
- **Description:** Hunts for TLS connections using a certificate serial number associated with a Mythic C2 server observed during active exploitation of Cisco Catalyst SD-WAN Manager vulnerabilities (CVE-2026-20122, CVE-2026-20128, CVE-2026-20133). Multiple threat clusters, including the suspected state-nexus actor UAT-8616, exploited these vulnerabilities beginning in early March 2026 following publication of proof-of-concept code. Post-exploitation activity included deployment of Mythic C2, Sliver, and AdaptixC2 implants. The Mythic C2 instance used a static TLS certificate with a known serial number, making it a high-fidelity, low-FP indicator that does not rely on IP addresses and remains valid until the attacker rotates the certificate.

- **UUID:** `d15e4732-114b-40fe-bb9c-8fb37e3c94bb`
- **Integration:** [network_traffic](https://docs.elastic.co/integrations/network_traffic)
- **Language:** `[ES|QL]`
- **Source File:** [Mythic C2 TLS Certificate Observed in Cisco SD-WAN Exploitation](../queries/command_and_control_cisco_sdwan_mythic_c2_tls_cert.toml)

## Query

```sql
FROM packetbeat-*, logs-network_traffic.* METADATA _id
| WHERE @timestamp > now() - 7 day
| WHERE event.category == "network" or event.category == "network_traffic"
| WHERE network.protocol == "tls"
| WHERE tls.server.x509.serial_number == "fece5b954e69b2c6a8d0a1029631a0d7"
| KEEP @timestamp, source.ip, source.port, destination.ip, destination.port, tls.server.x509.serial_number, tls.server.x509.subject.common_name, tls.server.x509.issuer.common_name, network.transport
| SORT @timestamp DESC
```

## Notes

- The certificate serial `fece5b954e69b2c6a8d0a1029631a0d7` was observed on port 7443 (Mythic C2 default) as well as 4445 and 31337 alongside AdaptixC2 infrastructure used by the same cluster.
- This indicator is durable: TLS cert serials do not rotate unless the attacker regenerates the certificate. Unlike IP-based IOCs, this remains actionable until the cert is replaced.
- A hit on this query should be treated as high-confidence attacker C2 communication. Immediately identify the source host, isolate if possible, and review for lateral movement.
- If the cert serial is no longer observed but the campaign continues, pivot to destination ports 4445, 7443, and 31337 combined with non-standard ASNs (Clouvider AS62240, ReliableSite AS23470).
- Requires network packet capture data ingested via Packetbeat or equivalent that populates `tls.server.x509.serial_number`.

## MITRE ATT&CK Techniques

- [T1071.001](https://attack.mitre.org/techniques/T1071/001)
- [T1573.002](https://attack.mitre.org/techniques/T1573/002)

## References

- https://blog.talosintelligence.com/sd-wan-ongoing-exploitation/
- https://www.cisa.gov/news-events/alerts/2026/04/20/cisa-adds-eight-known-exploited-vulnerabilities-catalog
- https://www.helpnetsecurity.com/2026/04/21/cisa-flags-another-cisco-catalyst-sd-wan-manager-bug-as-exploited-cve-2026-20133/

## License

- `Elastic License v2`

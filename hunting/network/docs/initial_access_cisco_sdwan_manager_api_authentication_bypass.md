# Cisco SD-WAN Manager API Authentication Bypass Log Indicators

---

## Metadata

- **Author:** Elastic
- **Description:** Hunts for Cisco-published log indicators of CVE-2026-76504 exploitation against Cisco Catalyst SD-WAN Manager.
The queries identify a successful POST to a percent-encoded form of `/j_security_check` in the service proxy access
log and an SD-WAN Manager application log associating the encoded endpoint with a `viptela-reserved-` service account.
The vulnerability allows an unauthenticated remote attacker to bypass API authentication and obtain admin privileges.

- **UUID:** `5bacdc3b-0163-4a49-aa9b-259a63954bf3`
- **Integration:** [tcp](https://docs.elastic.co/integrations/tcp), [udp](https://docs.elastic.co/integrations/udp)
- **Language:** `[ES|QL]`
- **Source File:** [Cisco SD-WAN Manager API Authentication Bypass Log Indicators](../queries/initial_access_cisco_sdwan_manager_api_authentication_bypass.toml)

## Query

```sql
FROM logs-* METADATA _id, _index
| WHERE @timestamp > NOW() - 30 days
| WHERE message LIKE "*%*"
    AND message RLIKE """.*POST /(j|%6[aA])(_|%5[fF])(s|%73)(e|%65)(c|%63)(u|%75)(r|%72)(i|%69)(t|%74)(y|%79)(_|%5[fF])(c|%63)(h|%68)(e|%65)(c|%63)(k|%6[bB]) HTTP/[0-9.]+" 200 .*"""
| KEEP
    @timestamp,
    host.name,
    observer.name,
    source.ip,
    message,
    _index,
    _id
| SORT @timestamp DESC
| LIMIT 1000
```

```sql
FROM logs-* METADATA _id, _index
| WHERE @timestamp > NOW() - 30 days
| WHERE message LIKE "*%*"
    AND message LIKE "*Request Stored in Map is (*"
    AND message LIKE "*for user (viptela-reserved-*"
    AND message RLIKE """.*/(j|%6[aA])(_|%5[fF])(s|%73)(e|%65)(c|%63)(u|%75)(r|%72)(i|%69)(t|%74)(y|%79)(_|%5[fF])(c|%63)(h|%68)(e|%65)(c|%63)(k|%6[bB]).*"""
| KEEP
    @timestamp,
    host.name,
    observer.name,
    user.name,
    message,
    _index,
    _id
| SORT @timestamp DESC
| LIMIT 1000
```

## Notes

- This hunt requires Cisco Catalyst SD-WAN Manager records normally stored in `/var/log/nms/containers/service-proxy/serviceproxy-access.log` or `/var/log/nms/vmanage-server.log`. It does not require HTTPS decryption because the appliance creates these records after terminating TLS.
- Cisco Catalyst SD-WAN Manager supports remote syslog, but confirm that the deployed release and logging configuration forward the two required log sources. If they are not forwarded, use a Cisco-supported method to relay or export the files to a separate collector. Do not install Elastic Agent directly on the appliance unless Cisco supports that deployment.
- On the separate collector, ingest forwarded records with the Custom TCP Logs or Custom UDP Logs integration and enable appropriate syslog parsing. The queries search `logs-*` so they cover the default `tcp.generic` and `udp.generic` datasets as well as customer-selected logs data streams.
- Before relying on the hunt, verify that representative records from both files arrive with the original request text retained in `message`. URI decoding or normalization during collection can remove the percent-encoding indicator and make these queries ineffective.
- Cisco's published example uses `%6a` for the `j` in `/%6a_security_check`, but Cisco states that encoding any one character in the endpoint can exploit the vulnerability. The queries therefore allow every character in `/j_security_check` to be literal or represented by its matching percent-encoded byte and separately require percent encoding in the event.
- The first query requires the Cisco-published successful access-log shape: a POST to the encoded endpoint with an HTTP 200 response. Review all source addresses in the forwarded-for chain and determine which address represents the originating client before blocking or attributing activity.
- The second query requires the Cisco-published application-log context linking the encoded request to a username beginning with `viptela-reserved-`. These are legitimate system service accounts; the percent-encoded authentication endpoint is the suspicious element.
- Authorized security testing may reproduce these indicators. Validate the source against approved scanner and assessment activity, but treat unexplained matches as high-priority possible compromise.
- If either query matches, preserve the relevant logs, collect an admin-tech file, review subsequent admin API actions and configuration changes, restrict management access, upgrade to a fixed release, and contact Cisco TAC. The absence of matches does not establish that the system is patched or uncompromised.

## MITRE ATT&CK Techniques

- [T1190](https://attack.mitre.org/techniques/T1190)

## References

- https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-webauth-xr8beuuU
- https://www.bleepingcomputer.com/news/security/cisco-warns-of-new-sd-wan-authentication-bypass-zero-day-exploited-in-attacks/
- https://www.cisco.com/c/en/us/td/docs/routers/sdwan/17-x/systems-interfaces/systems-interfaces-guide-17-x/system-logging.html
- https://www.elastic.co/docs/reference/integrations/tcp/
- https://www.elastic.co/docs/reference/integrations/udp/

## License

- `Elastic License v2`

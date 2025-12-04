# Potential Spoofed `microsoftonline.com` via Fuzzy Match

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies potential spoofed domain activity targeting Microsoft online services by detecting fuzzy matches to the domain `microsoftonline.com`. The approach uses approximate string matching (fuzziness) on domain and URL fields, then scores each result by similarity. A static confidence threshold is applied to filter out high-confidence legitimate matches while surfacing potential typosquats and lookalikes.

This technique is useful for identifying phishing campaigns, misconfigured infrastructure, or domain squatting activity targeting Microsoft users and applications. It relies on string similarity scoring and known-good domain exclusions to reduce false positives and focus the hunt on medium- to high-risk spoofed domains.

- **UUID:** `e912f5c6-eed3-11ef-a5d7-6f9f7a1e2e00`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [network_traffic](https://docs.elastic.co/integrations/network_traffic), [system](https://docs.elastic.co/integrations/system), [azure](https://docs.elastic.co/integrations/azure), [o365](https://docs.elastic.co/integrations/o365), [windows](https://docs.elastic.co/integrations/windows)
- **Language:** `[ES|QL]`
- **Source File:** [Potential Spoofed `microsoftonline.com` via Fuzzy Match](../queries/potentially_spoofed_microsoft_authentication_domain.toml)

## Query

```sql
FROM logs-* METADATA _score
| WHERE (
    url.domain IS NOT NULL OR
    url.original IS NOT NULL OR
    destination.domain IS NOT NULL OR
    dns.question.name IS NOT NULL
)
| EVAL domain = COALESCE(url.domain, url.original, destination.domain, dns.question.name)::STRING
| WHERE NOT(
    domain RLIKE "^(login|portal|api)\\.microsoftonline\\.com$" OR
    domain RLIKE ".*\\.onmicrosoft\\.com$" OR
    domain == "microsoftonline.com")
| WHERE (
    match(url.domain, "microsoftonline.com", { "fuzziness": "AUTO", "max_expansions": 10 }) OR
    match(url.original, "microsoftonline.com", { "fuzziness": "AUTO", "max_expansions": 10 }) OR
    match(destination.domain, "microsoftonline.com", { "fuzziness": "AUTO", "max_expansions": 10 }) OR
    match(dns.question.name, "microsoftonline.com", { "fuzziness": "AUTO", "max_expansions": 10 })
)
| EVAL confidence = CASE(
    _score >= 5.999, "low",
    _score > 4, "medium",
    "high"
)
| WHERE confidence != "low"
   OR domain IN ("micsrosoftonline.com", "outlook-office.micsrosoftonline.com")
| SORT _score DESC
| KEEP @timestamp, source.ip, user.id, domain, _score, confidence
```

## Notes

- Investigate domains that resemble `microsoftonline.com` but have slight character substitutions (e.g., `micros0ftonline.com`, `m1crosoftonline.com`).
- Fuzzy matching assigns a `_score` based on edit distance. Higher scores mean a closer match to the legitimate domain.
- Only medium- and high-confidence results are surfaced by excluding `_score >= 6`, which usually represents exact or near-exact matches.
- Legitimate Microsoft domains like `login.microsoftonline.com`, `portal.microsoftonline.com`, and tenant domains ending in `.onmicrosoft.com` are excluded from results to reduce noise.
- Results are ranked by `_score DESC` and tagged with a confidence level: `low`, `medium`, or `high`.
- This query is best used interactively during hunts and may require tuning for specific environments with high Microsoft traffic.

## MITRE ATT&CK Techniques

- [T1566.002](https://attack.mitre.org/techniques/T1566/002)
- [T1583.001](https://attack.mitre.org/techniques/T1583/001)

## References

- https://www.microsoft.com/en-us/security/blog/2025/05/27/new-russia-affiliated-actor-void-blizzard-targets-critical-sectors-for-espionage/

## License

- `Elastic License v2`

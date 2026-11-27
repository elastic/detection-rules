# Unusual Distributed Fan-In Relative to Historical Baseline

---

## Metadata

- **Author:** Elastic
- **Description:** Hunts for a recent distributed fan-in spike in Network Packet Capture flow telemetry relative to the historical
behavior of the same destination service and capture agent. The query compares distinct external source and flow
cardinality in the most recently completed five-minute bucket with a seven-day per-service baseline using median
absolute deviation. Results are potential traffic anomalies for investigation and do not independently establish a
denial-of-service attack or service impact.

- **UUID:** `e285a9a6-568e-4f5f-be0b-897cc66d68b2`
- **Integration:** [network_traffic](https://docs.elastic.co/integrations/network_traffic)
- **Language:** `[ES|QL]`
- **Source File:** [Unusual Distributed Fan-In Relative to Historical Baseline](../queries/impact_unusual_distributed_fan_in_relative_to_historical_baseline.toml)

## Query

```sql
FROM logs-network_traffic.flow-*
| WHERE @timestamp >= NOW() - 7 day
    AND data_stream.dataset == "network_traffic.flow"
    AND event.action == "network_flow"
    AND event.agent_id_status == "verified"
    AND agent.id IS NOT NULL
    AND network_traffic.flow.id IS NOT NULL
    AND source.ip IS NOT NULL
    AND destination.ip IS NOT NULL
    AND destination.port IS NOT NULL
    AND network.transport IN ("tcp", "udp")
    AND NOT CIDR_MATCH(
      source.ip,
      "0.0.0.0/8",
      "10.0.0.0/8",
      "100.64.0.0/10",
      "127.0.0.0/8",
      "169.254.0.0/16",
      "172.16.0.0/12",
      "192.0.0.0/24",
      "192.0.2.0/24",
      "192.168.0.0/16",
      "198.18.0.0/15",
      "198.51.100.0/24",
      "203.0.113.0/24",
      "224.0.0.0/4",
      "240.0.0.0/4",
      "::/128",
      "::1/128",
      "2001:db8::/32",
      "fc00::/7",
      "fe80::/10",
      "ff00::/8"
    )
| EVAL Esql.time_window = DATE_TRUNC(5 minutes, @timestamp)
| STATS
    Esql.distinct_flow_count = COUNT_DISTINCT(network_traffic.flow.id),
    Esql.distinct_source_count = COUNT_DISTINCT(source.ip),
    Esql.report_count = COUNT(*)
  BY Esql.time_window, agent.id, destination.ip, destination.port, network.transport
| WHERE Esql.time_window <= DATE_TRUNC(5 minutes, NOW()) - 5 minutes
| EVAL Esql.is_candidate_window =
    Esql.time_window == DATE_TRUNC(5 minutes, NOW()) - 5 minutes
| STATS
    Esql.current_flow_count = MAX(Esql.distinct_flow_count) WHERE Esql.is_candidate_window == true,
    Esql.current_source_count = MAX(Esql.distinct_source_count) WHERE Esql.is_candidate_window == true,
    Esql.current_report_count = MAX(Esql.report_count) WHERE Esql.is_candidate_window == true,
    Esql.baseline_flow_median = MEDIAN(Esql.distinct_flow_count) WHERE Esql.is_candidate_window == false,
    Esql.baseline_flow_mad =
      MEDIAN_ABSOLUTE_DEVIATION(Esql.distinct_flow_count) WHERE Esql.is_candidate_window == false,
    Esql.baseline_source_median = MEDIAN(Esql.distinct_source_count) WHERE Esql.is_candidate_window == false,
    Esql.baseline_source_mad =
      MEDIAN_ABSOLUTE_DEVIATION(Esql.distinct_source_count) WHERE Esql.is_candidate_window == false,
    Esql.baseline_bucket_count = COUNT(*) WHERE Esql.is_candidate_window == false,
    Esql.candidate_bucket_count = COUNT(*) WHERE Esql.is_candidate_window == true
  BY agent.id, destination.ip, destination.port, network.transport
| EVAL
    Esql.flow_scale = CASE(
      Esql.baseline_flow_mad > 0,
      1.4826 * Esql.baseline_flow_mad,
      Esql.baseline_flow_median > 0,
      Esql.baseline_flow_median,
      1.0
    ),
    Esql.source_scale = CASE(
      Esql.baseline_source_mad > 0,
      1.4826 * Esql.baseline_source_mad,
      Esql.baseline_source_median > 0,
      Esql.baseline_source_median,
      1.0
    )
| EVAL
    Esql.flow_deviation_score =
      (TO_DOUBLE(Esql.current_flow_count) - Esql.baseline_flow_median) / Esql.flow_scale,
    Esql.source_deviation_score =
      (TO_DOUBLE(Esql.current_source_count) - Esql.baseline_source_median) / Esql.source_scale
| WHERE
    Esql.candidate_bucket_count == 1
    AND Esql.baseline_bucket_count >= 12
    AND Esql.current_source_count >= 10
    AND Esql.flow_deviation_score >= 6
    AND Esql.source_deviation_score >= 6
| KEEP
    agent.id,
    destination.ip,
    destination.port,
    network.transport,
    Esql.current_flow_count,
    Esql.current_source_count,
    Esql.current_report_count,
    Esql.baseline_flow_median,
    Esql.baseline_flow_mad,
    Esql.flow_deviation_score,
    Esql.baseline_source_median,
    Esql.baseline_source_mad,
    Esql.source_deviation_score,
    Esql.baseline_bucket_count
| SORT Esql.flow_deviation_score DESC, Esql.source_deviation_score DESC
| LIMIT 100
```

## Notes

- The query evaluates each verified Elastic Agent, destination IP, destination port, and transport independently so different capture agents and services do not share a baseline.
- The candidate bucket is the most recently completed five-minute UTC bucket. Adjust the candidate offset when flow ingestion is delayed.
- The baseline includes only five-minute buckets containing matching external-source traffic. Missing zero-traffic buckets are not synthesized, which generally makes the baseline more conservative for sparse services.
- Median absolute deviation is used because internet-facing service traffic is often skewed and bursty. The 1.4826 factor places MAD on a standard-deviation-like scale for easier interpretation.
- The hunt requires at least 12 active historical buckets, 10 current external sources, and flow and source deviation scores of at least 6. These are safety and statistical floors rather than claims that a fixed traffic volume is malicious.
- Distinct flow IDs provide an active-flow observation measure without summing repeated cumulative packet or byte reports. Reporting cadence, flow timeout, NAT, spoofing, and overlapping sensors still affect the result.
- COUNT_DISTINCT, MEDIAN, and MEDIAN_ABSOLUTE_DEVIATION can be approximate. Review raw flow, firewall, load-balancer, DDoS-protection, and service-health telemetry before escalation.
- Restrict destination scope to organization-owned services or protected address ranges when that topology is known.
- A synthetic RTA can validate bucket assignment and score-threshold behavior, but it cannot establish production query cost, benign noise, or attack recall.
- The seven-day high-cardinality aggregation can be resource intensive. Measure it on representative data and narrow its scope before promotion to a scheduled hunt, building-block rule, or detection rule.

## MITRE ATT&CK Techniques

- [T1498](https://attack.mitre.org/techniques/T1498)

## References

- https://attack.mitre.org/techniques/T1498/
- https://www.elastic.co/docs/reference/integrations/network_traffic
- https://www.elastic.co/docs/reference/query-languages/esql/functions-operators/aggregation-functions/median_absolute_deviation

## License

- `Elastic License v2`

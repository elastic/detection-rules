# Monitoring for Latency Anomalies

---

## Metadata

- **Integration:** aws_bedrock.invocation
- **Author:** Elastic
- **UUID:** 3708787b-811b-43b1-b2e7-c7276b8db48c

## Hypothesis

Detects unusually high initial response latencies in LLM interactions, which may indicate network attacks or system inefficiencies.

## Analytic

```sql
from logs-aws_bedrock.invocation-*
  | WHERE @timestamp > NOW() - 1 DAY
  | EVAL response_delay_seconds = gen_ai.performance.start_response_time / 1000
  | WHERE response_delay_seconds > 5
  | STATS max_response_delay = max(response_delay_seconds),
          request_count = count() BY gen_ai.user.id
  | WHERE request_count > 3
  | SORT max_response_delay DESC
```

## Notes

- This analytic helps identify delays in LLM responses that are outside expected performance parameters, possibly due to malicious disruptions like DDoS attacks or from operational inefficiencies.
- Review the incidents flagged by this analytic to understand the context and potential sources of latency. This can include network configurations, resource allocation, or external network pressures.
- Effective logging and monitoring setup are essential to capture relevant latency metrics accurately. Ensure system clocks and time syncing are properly configured to avoid false positives.
- Gather comprehensive logs that detail the request and response timestamps, user IDs, and session details for thorough investigation and evidence collection in case of security incidents.

## MITRE ATT&CK Techniques

- Denial of ML Service - AML.T0029

## References

- https://www.elastic.co/security-labs/TBD

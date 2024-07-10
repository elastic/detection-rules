# AWS Bedrock LLM Latency Anomalies

---

## Metadata

- **Author:** Elastic
- **Description:** This analytic helps identify delays in LLM responses that are outside expected performance parameters, possibly due to malicious disruptions like DDoS attacks or from operational inefficiencies.

- **UUID:** `991b55c3-6327-4af6-8e0c-5d4870748369`
- **Integration:** [aws_bedrock.invocation](https://docs.elastic.co/integrations/aws_bedrock)
- **Language:** `[ES|QL]`
- **Source File:** [AWS Bedrock LLM Latency Anomalies](../queries/aws_bedrock_latency_anomalies_detection.toml)

## Query

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

- Review the incidents flagged by this analytic to understand the context and potential sources of latency. This can include network configurations, resource allocation, or external network pressures.
- Effective logging and monitoring setup are essential to capture relevant latency metrics accurately. Ensure system clocks and time syncing are properly configured to avoid false positives.
- Gather comprehensive logs that detail the request and response timestamps, user IDs, and session details for thorough investigation and evidence collection in case of security incidents.

## MITRE ATT&CK Techniques

- [AML.T0029](https://atlas.mitre.org/techniques/AML.T0029)

## References

- https://www.elastic.co/security-labs/elastic-advances-llm-security
- https://owasp.org/www-project-top-10-for-large-language-model-applications/

## License

- `Elastic License v2`

# Monitoring for Latency Anomalies

---

## Metadata

**Author:** Elastic
**UUID:** 3708787b-811b-43b1-b2e7-c7276b8db48c

## Query

```sql
from logs-aws_bedrock.invocation-*
  | WHERE @timestamp > NOW() - 1 DAY
  | EVAL gen_ai_start_response_ts = TO_DATETIME(@timestamp) - (gen_ai.performance.start_response_time / 1000)
  | WHERE DATE_DIFF("seconds", gen_ai_start_response_ts, @timestamp) > 5
  | STATS max_latency = max(DATE_DIFF("seconds", gen_ai_start_response_ts, @timestamp)),
          request_count = count() BY gen_ai.user.id
  | WHERE request_count > 3
  | SORT max_latency DESC

```

## Description

This updated query monitors the time it takes for an LLM to start sending a response after receiving a request, focusing on the initial response latency. By calculating the difference between the expected start of the response and the recorded response time, it identifies when responses are significantly delayed. Anomalous latencies can be symptomatic of issues such as network attacks (e.g., DDoS) or system inefficiencies that need to be addressed. By tracking and analyzing latency metrics, organizations can ensure that their systems are running efficiently and securely, and can quickly respond to potential threats that might manifest as abnormal delays.

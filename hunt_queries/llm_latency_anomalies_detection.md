# Monitoring for Latency Anomalies

---

## Metadata

**Author:** ["Elastic"]
**License:** "Elastic License v2"
**Creation Date:** 2024-05-01
**Updated Date:** 2024-05-01

## Query

```sql
from logs-aws_bedrock.invocation-*
  | WHERE @timestamp > NOW() - 1 DAY
  | EVAL gen_ai_response_ts = TO_DATETIME(gen_ai.response.timestamp),
        ingest_ts = TO_DATETIME(@timestamp)
  | WHERE DATE_DIFF("seconds", gen_ai_response_ts, ingest_ts) > 5
  | STATS max_latency = max(DATE_DIFF("seconds", gen_ai_response_ts, ingest_ts)),
          max_response_time = max(gen_ai.performance.response_time),
          request_count = count() BY gen_ai.user.id
  | WHERE request_count > 3 AND gen_ai.performance.response_time >= 60
  | SORT max_latency DESC, max_response_time DESC
```

## Description

This query checks for significant delays between the timestamps logged by the system and those recorded by AWS CloudWatch.

## Security Relevance

Anomalous latencies can be symptomatic of issues such as network attacks or system inefficiencies that need to be addressed to ensure efficient and secure system operations.

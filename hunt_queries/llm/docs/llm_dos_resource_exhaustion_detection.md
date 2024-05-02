# Denial of Service or Resource Exhaustion Attacks Detection

---

## Metadata

**Author:** Elastic
**UUID:** dc181967-c32c-46c9-b84b-ec4c8811c6a0

**Integration:** aws_bedrock.invocation

## Query

```sql
from logs-aws_bedrock.invocation-*
 | WHERE @timestamp > NOW() - 1 DAY
   AND (
     gen_ai.usage.prompt_tokens > 8000 OR
     gen_ai.usage.completion_tokens > 8000 or
     gen_ai.performance.request_size > 8000
   )
 | STATS max_prompt_tokens = max(gen_ai.usage.prompt_tokens),
         max_request_tokens = max(gen_ai.performance.request_size),
         max_completion_tokens = max(gen_ai.usage.completion_tokens),
         request_count = count() BY cloud.account.id
 | WHERE request_count > 1
 | SORT max_prompt_tokens, max_request_tokens, max_completion_tokens DESC

```

## Description

This query identifies high-volume token usage which could be indicative of abuse or an attempted denial of service (DoS) attack. Monitoring for unusually high token counts (input or output) helps detect patterns that could slow down or overwhelm the system, potentially leading to service disruptions. Given each application may leverage a different token volume, we’ve chosen a simple threshold based on our existing experience that should cover basic use cases. This form of monitoring helps detect potential concerns with system availability and performance. It helps in the early detection of DoS attacks or abusive behavior that could degrade service quality for legitimate users. By aggregating and analyzing token usage by account, security teams can pinpoint sources of potentially malicious traffic and take appropriate measures.

## References

- https://www.elastic.co/security-labs/TBD

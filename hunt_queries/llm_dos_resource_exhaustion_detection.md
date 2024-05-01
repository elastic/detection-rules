# Denial of Service or Resource Exhaustion Attacks Detection

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

This query identifies high-volume token usage which could be indicative of abuse or an attempted denial of service (DoS) attack.

## Security Relevance

This monitoring helps detect potential concerns with system availability and performance, aiding in the early detection of DoS attacks or abusive behavior.

# Sensitive Content Refusal Detection

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
     gen_ai.completion LIKE "*I cannot provide any information about*"
     AND gen_ai.completion LIKE "*end_turn*"
   )
 | STATS user_request_count = count() BY gen_ai.user.id
 | WHERE user_request_count >= 3
```

## Description

This query detects instances where the model explicitly refuses to provide information on potentially sensitive or restricted topics multiple times.

## Security Relevance

Monitoring LLM refusals helps to identify attempts to probe the model for sensitive data or to exploit it in a manner that could lead to the leakage of proprietary or restricted information.

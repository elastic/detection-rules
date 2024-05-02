# Sensitive Content Refusal Detection

---

## Metadata

**Author:** Elastic
**UUID:** 8fabae86-7ed2-4006-9623-5db28164f374

**Integration:** aws_bedrock.invocation

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

This query is used to detect instances where the model explicitly refuses to provide information on potentially sensitive or restricted topics multiple times. Combined with predefined formatted outputs, the use of specific phrases like 'I cannot provide any information about' within the output content indicates that the model has been triggered by a user prompt to discuss something it's programmed to treat as confidential or inappropriate. Monitoring LLM refusals helps to identify attempts to probe the model for sensitive data or to exploit it in a manner that could lead to the leakage of proprietary or restricted information. By analyzing the patterns and frequency of these refusals, security teams can investigate if there are targeted attempts to breach information security policies.

## References

- https://www.elastic.co/security-labs/TBD

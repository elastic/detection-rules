# Sensitive Content Refusal Detection

---

## Metadata

- **Integration:** aws_bedrock.invocation
- **Author:** Elastic
- **UUID:** 8fabae86-7ed2-4006-9623-5db28164f374

## Hypothesis

Detects repeated refusals by an LLM to engage with sensitive or restricted topics, which might indicate attempts to probe the model for sensitive information.

## Analytic

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

## Notes

- This analytic flags multiple instances of LLM refusals to respond to sensitive prompts, helping to maintain ethical guidelines and compliance standards.
- Examine flagged interactions for patterns or anomalies in user requests that may indicate malicious intent or probing of model boundaries.
- Regularly review and update the phrases that trigger refusals to adapt to new ethical guidelines and compliance requirements.
- Ensure that data logs contain enough detail to provide context around the refusal, which will aid in subsequent investigations by security teams.

## MITRE ATT&CK Techniques

- LLM Prompt Injection - AML.T0051

## References

- https://www.elastic.co/security-labs/TBD

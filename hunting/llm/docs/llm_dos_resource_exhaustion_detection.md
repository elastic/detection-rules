# Denial of Service or Resource Exhaustion Attacks Detection

---

## Metadata

- **Author:** Elastic
- **UUID:** `dc181967-c32c-46c9-b84b-ec4c8811c6a0`
- **Integration:** `aws_bedrock.invocation`
- **Language:** `ES|QL`

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

## Notes

- This query identifies unusual spikes in token usage that may indicate malicious attempts to disrupt services. High token usage can strain system resources and degrade performance, aligning with tactics observed in DoS attacks.
- Consider reviewing the context of high token requests to differentiate between legitimate heavy usage and potential abuse. Monitor the source of requests and patterns over time for better assessment.
- Ensure logging and monitoring are correctly configured to capture detailed metrics on token usage. This will facilitate accurate detection and allow for a quick response to potential threats.
- Collect evidence from logs that detail the timestamp, user ID, session information, and token counts for incidents flagged by this analytic. This information will be crucial for forensic analysis in the event of a security incident.
## MITRE ATT&CK Techniques

- [AML.T0034](https://atlas.mitre.org/techniques/AML.T0034)

## References

- https://www.elastic.co/security-labs/elastic-advances-llm-security
- https://owasp.org/www-project-top-10-for-large-language-model-applications/
- [Denial of Service or Resource Exhaustion Attacks Detection](../queries/llm_dos_resource_exhaustion_detection.toml)
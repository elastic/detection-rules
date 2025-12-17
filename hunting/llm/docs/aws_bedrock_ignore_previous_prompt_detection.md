# AWS Bedrock LLM Ignore Previous Prompt Detection

---

## Metadata

- **Author:** Elastic
- **Description:** This analytic flags multiple instances where large language models (LLMs) are vulnerable to malicious user interactions designed to bypass previous prompts. This can lead to the generation of inappropriate or harmful content, resulting in direct LLM prompt injection.
- **UUID:** `131e5887-463a-46a1-a44e-b96361bc6cbc`
- **Integration:** [aws_bedrock.invocation](https://docs.elastic.co/integrations/aws_bedrock)
- **Language:** `[ES|QL]`
- **Source File:** [AWS Bedrock LLM Ignore Previous Prompt Detection](../queries/aws_bedrock_ignore_previous_prompt_detection.toml)

## Query

```sql
from logs-aws_bedrock.invocation-*
 |EVAL lowercase_prompt = TO_LOWER(gen_ai.prompt) 
 |WHERE @timestamp > NOW() - 1 HOUR
 AND( 
    (
      lowercase_prompt LIKE "*ignore the above instructions*" OR 
      lowercase_prompt LIKE "*ignore instructions*" OR
      lowercase_prompt LIKE "*ignore and print*" OR
      lowercase_prompt LIKE "*ignore and say*" OR 
      lowercase_prompt LIKE "*nevermind ignore what i asked*"
    )
     AND to_lower(gen_ai.completion) LIKE "*end_turn*"
   )
 | STATS user_request_count = count(*) BY gen_ai.user.id
 | WHERE user_request_count >= 2
```

## Notes

- Examine flagged interactions for patterns or anomalies in user requests that may indicate malicious intent to expose LLM vulnerabilities
- Regularly review and update the phrases that trigger ignore previous prompt attacks to adapt to new ethical guidelines and compliance requirements.
- Ensure that data logs contain enough detail to provide context around the refusal, which will aid in subsequent investigations by security teams.

## MITRE ATT&CK Techniques

- [AML.T0051.000](https://atlas.mitre.org/techniques/AML.T0051.000)

## References

- https://www.elastic.co/security-labs/elastic-advances-llm-security
- https://github.com/agencyenterprise/PromptInject?tab=readme-ov-file

## License

- `Elastic License v2`

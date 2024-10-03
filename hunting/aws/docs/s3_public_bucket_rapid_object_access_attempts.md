# S3 Public Bucket Rapid Object Access Attempts

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies when an anonymous user, outside of the known AWS IP ranges, makes multiple `GetObject` requests to a public S3 bucket. Rapid access to objects in a public S3 bucket may indicate an adversary attempting to exfiltrate data or perform reconnaissance on the bucket contents.

- **UUID:** `ef579900-75ef-11ef-b47f-f661ea17fbcc`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [S3 Public Bucket Rapid Object Access Attempts](../queries/s3_public_bucket_rapid_object_access_attempts.toml)

## Query

```sql
from logs-aws.cloudtrail*
| where @timestamp > now() - 7 day
| where event.provider == "s3.amazonaws.com" and event.action == "GetObject" and cloud.account.id == "anonymous"
    and NOT CIDR_MATCH(source.ip,
       "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
       "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8",
       "52.95.0.0/16","54.239.0.0/16", "18.0.0.0/8",
       "3.0.0.0/8", "35.0.0.0/8")
| DISSECT aws.cloudtrail.request_parameters "{%{?bucket_name_key}=%{bucket_name}, %{?host_key}=%{bucket_location}, %{?object_key}=%{bucket_object}}"
| STATS s3_bucket_access_count = COUNT(bucket_object) by bucket_name
| WHERE s3_bucket_access_count >= 15
```

## Notes

- Use the `bucket_name` field to identify the public S3 bucket that the objects were accessed from
- Use the `bucket_object` field to identify the objects that were accessed
- Review bucket policies and access control lists (ACLs) to ensure that the bucket is not publicly accessible
- 

## MITRE ATT&CK Techniques

- [T1530](https://attack.mitre.org/techniques/T1530)

## License

- `Elastic License v2`

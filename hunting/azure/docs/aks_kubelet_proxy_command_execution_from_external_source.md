# AKS Kubelet nodes/proxy Command Execution from an External Source IP

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt surfaces command execution against a node's Kubelet through the AKS (Azure Kubernetes Service) API server nodes/proxy subresource where the request originates from an external (non-internal) client IP. A principal holding nodes/proxy can tunnel through the API server to a node's Kubelet and run commands in any pod on that node (kubeletctl, Peirates), and even a GET to the /exec endpoint is remote code execution because the Kubelet maps the WebSocket upgrade handshake to the RBAC get verb. AKS kube-audit fields are stored under a flattened object, so the query reads them via JSON_EXTRACT over _source and keeps only the command-execution Kubelet endpoints (run, exec, attach, portforward, cri) whose source IPs still contain a public address after internal ranges are stripped, isolating externally operated activity from in-cluster monitoring.
- **UUID:** `3eb22dca-7c38-4885-9fc3-1d9f2e6d552c`
- **Integration:** [azure](https://docs.elastic.co/integrations/azure)
- **Language:** `[ES|QL]`
- **Source File:** [AKS Kubelet nodes/proxy Command Execution from an External Source IP](../queries/aks_kubelet_proxy_command_execution_from_external_source.toml)

## Query

```sql
FROM logs-azure.platformlogs-* METADATA _source
| WHERE @timestamp > NOW() - 7 day
    AND azure.platformlogs.category == "kube-audit"
| EVAL
    kube_user   = TO_STRING(JSON_EXTRACT(_source, "$.azure.platformlogs.properties.log.user.username")),
    obj_res     = TO_STRING(JSON_EXTRACT(_source, "$.azure.platformlogs.properties.log.objectRef.resource")),
    obj_sub     = TO_STRING(JSON_EXTRACT(_source, "$.azure.platformlogs.properties.log.objectRef.subresource")),
    request_uri = TO_STRING(JSON_EXTRACT(_source, "$.azure.platformlogs.properties.log.requestURI")),
    source_ips  = TO_STRING(JSON_EXTRACT(_source, "$.azure.platformlogs.properties.log.sourceIPs"))
// only Kubelet command-execution endpoints, not /metrics, /stats, /pods monitoring
| WHERE obj_res == "nodes" AND obj_sub == "proxy"
    AND request_uri RLIKE ".*/proxy/(run|exec|attach|portforward|portForward|cri)(/|\?|$).*"
// strip internal / RFC1918 ranges; keep only events that still carry an external client IP
| EVAL external_ips = REPLACE(source_ips, "(10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+|127\.[0-9]+\.[0-9]+\.[0-9]+)", "")
| WHERE external_ips RLIKE ".*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*"
| KEEP @timestamp, kube_user, source_ips, request_uri
| SORT @timestamp DESC
| LIMIT 100
```

## Notes

- This is an ES|QL query returning results in a tabular format. Pivot from `kube_user`, `request_uri`, or `source_ips` into the raw kube-audit event for the full request context.
- AKS kube-audit fields live under `azure.platformlogs.properties`, which is a `flattened` object; ES|QL cannot reference the subfields as columns, so the query extracts them with `JSON_EXTRACT(_source, "$.azure.platformlogs.properties.log.<field>")` using the nested JSON path. Reading `_source` is expensive, so scope the time range narrowly and widen only as needed.
- Endpoint classification is in `request_uri`: `/proxy/run`, `/proxy/exec`, `/proxy/attach`, `/proxy/portforward`, and `/proxy/cri` are command execution; `/proxy/metrics`, `/proxy/stats`, `/proxy/pods`, and `/proxy/runningpods` are benign monitoring and reconnaissance.
- `sourceIPs` is an array. The API server appends the internal konnectivity/API-server hop (for example `172.31.x`) to every proxied request, so a naive `NOT sourceIPs:172.*` drops everything. This hunt strips internal RFC1918 ranges and keeps events that still contain a public IP, which for an externally operated attack is the operator's real client address.
- Blind spots: only API-server-proxied Kubelet access appears in kube-audit. Direct access to the Kubelet on port 10250 (kubeletctl's default) never reaches the API server or these logs. An in-cluster pivot (compromised pod) shows only internal IPs and will not match the external-IP filter; remove the last two lines to catch that case at the cost of more monitoring noise.
- This technique has been observed with kubeletctl and Peirates for lateral movement and privilege escalation to cluster administrator.

## MITRE ATT&CK Techniques

- [T1609](https://attack.mitre.org/techniques/T1609)
- [T1210](https://attack.mitre.org/techniques/T1210)

## References

- https://horizon3.ai/attack-research/when-read-only-isnt-k8s-nodes-proxy-get-to-rce/
- https://stratus-red-team.cloud/attack-techniques/kubernetes/k8s.privilege-escalation.nodes-proxy/
- https://www.cyberark.com/resources/threat-research-blog/using-kubelet-client-to-attack-the-kubernetes-cluster
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/
- https://github.com/inguardians/peirates

## License

- `Elastic License v2`

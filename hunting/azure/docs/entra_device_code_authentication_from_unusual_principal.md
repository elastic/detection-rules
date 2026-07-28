# Entra ID Device Code Authentication from Unusual Principal

---

## Metadata

- **Author:** Elastic
- **Description:** This hunt identifies high-fidelity device code phishing follow-on activity in Azure Entra ID sign-in logs. Real device code phishing campaigns (Storm-2372, APT29, AADInternals/ROADTools/TokenSmith tradecraft) succeed when a victim completes the OAuth device code flow, granting the adversary tokens for first-party Microsoft client applications such as Microsoft Azure CLI, Microsoft Azure PowerShell, Microsoft Graph Command Line Tools, Windows Terminal, or Visual Studio Code. The adversary then exchanges those tokens against high-value resources — Azure Resource Manager (cloud control plane), Microsoft Graph (directory and mailbox enumeration), Office 365 Exchange Online (mail), or Windows Azure AD (directory) — typically from an unmanaged, non-inventoried device.

This query filters away the dominant benign patterns observed in production telemetry: Microsoft Authentication Broker → Device Registration Service flows (legitimate device join), incoming `primaryRefreshToken` exchanges (post-auth refresh, not initial access), Microsoft-owned source ASNs, and well-managed compliant devices. What remains is the suspicious shape: a first-party CLI client + high-value resource + single-factor or no conditional access + missing device detail + non-Microsoft source ASN.

- **UUID:** `b54528ca-eec8-11ef-b314-f661ea17fbce`
- **Integration:** [azure](https://docs.elastic.co/integrations/azure)
- **Language:** `[ES|QL]`
- **Source File:** [Entra ID Device Code Authentication from Unusual Principal](../queries/entra_device_code_authentication_from_unusual_principal.toml)

## Query

```sql
FROM logs-azure.signinlogs-*

// scope to Entra ID sign-in events
| WHERE @timestamp > now() - 14 day
  AND event.dataset == "azure.signinlogs"
  AND event.category == "authentication"

// device code grant flow (initial or token exchange originating from device code)
  AND (
    azure.signinlogs.properties.authentication_protocol == "deviceCode"
    OR azure.signinlogs.properties.original_transfer_method == "Device code flow"
  )

// successful authentications only
  AND azure.signinlogs.properties.status.error_code == 0

// drop Microsoft Authentication Broker - benign device-join flow
  AND azure.signinlogs.properties.app_id != "29d9ed98-a469-4536-ade2-f981bc1d605e"

// drop Device Registration Service as resource - benign device-join target
  AND azure.signinlogs.properties.resource_id != "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9"

// drop primaryRefreshToken / refreshToken exchanges - we want initial token issuance, not refresh
  AND (
    azure.signinlogs.properties.incoming_token_type IS NULL
    OR azure.signinlogs.properties.incoming_token_type NOT IN ("primaryRefreshToken", "refreshToken")
  )

// focus on first-party Microsoft CLI / dev tooling commonly abused in device code phishing
  AND azure.signinlogs.properties.app_id IN (
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  // Microsoft Azure CLI
    "1950a258-227b-4e31-a9cf-717495945fc2",  // Microsoft Azure PowerShell
    "14d82eec-204b-4c2f-b7e8-296a70dab67e",  // Microsoft Graph Command Line Tools
    "245e1dee-74ef-4257-a8c8-8208296e1dfd",  // Windows Terminal
    "aebc6443-996d-45c2-90f0-388ff96faa56",  // Visual Studio Code
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264",  // Microsoft Teams
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  // Microsoft Office
    "ab9b8c07-8f02-4f72-87fa-80105867a763"   // OneDrive SyncEngine
  )

// focus on high-value target resources (cloud control plane, directory, mail, identity)
  AND azure.signinlogs.properties.resource_id IN (
    "797f4846-ba00-4fd7-ba43-dac1f8f63013",  // Azure Resource Manager
    "00000003-0000-0000-c000-000000000000",  // Microsoft Graph
    "00000002-0000-0ff1-ce00-000000000000",  // Office 365 Exchange Online
    "00000002-0000-0000-c000-000000000000",  // Windows Azure Active Directory
    "0000000a-0000-0000-c000-000000000000"   // Microsoft Intune
  )

// drop Microsoft-owned source ASNs (legitimate Azure-hosted operations)
// re-enable if hunting Azure-infrastructure abuse
  AND (source.as.number IS NULL OR source.as.number != 8075)

// suspicious posture: SFA OR no conditional access OR missing device detail
  AND (
    azure.signinlogs.properties.authentication_requirement == "singleFactorAuthentication"
    OR azure.signinlogs.properties.conditional_access_status == "notApplied"
    OR (
      azure.signinlogs.properties.device_detail.is_compliant IS NULL
      AND azure.signinlogs.properties.device_detail.is_managed IS NULL
    )
    OR (
      azure.signinlogs.properties.device_detail.is_compliant == false
      AND azure.signinlogs.properties.device_detail.is_managed == false
    )
  )

// aggregate by identity + client + resource posture
| STATS
    auth_count = COUNT(*),
    first_seen = MIN(@timestamp),
    last_seen = MAX(@timestamp),
    src_ips = VALUES(source.ip),
    src_asns = VALUES(source.as.organization.name),
    countries = VALUES(source.geo.country_iso_code),
    user_agents = VALUES(user_agent.original),
    correlation_ids = VALUES(azure.signinlogs.properties.correlation_id),
    session_ids = VALUES(azure.signinlogs.properties.session_id)
  BY
    azure.signinlogs.properties.user_principal_name,
    azure.signinlogs.properties.app_display_name,
    azure.signinlogs.properties.resource_display_name,
    azure.signinlogs.properties.authentication_requirement

// surface low-volume / first-time patterns - rare combinations are highest interest
| WHERE auth_count < 10
| SORT first_seen DESC
| LIMIT 100
```

## Notes

- Microsoft Authentication Broker (29d9ed98-a469-4536-ade2-f981bc1d605e) is intentionally excluded — its device code flows almost always represent legitimate device-join / PRT acquisition. Adversary-driven device code phishing in production telemetry overwhelmingly uses Azure CLI / PowerShell / Graph CLI / Windows Terminal / VS Code as the requesting client.
- Device code flow IS MFA-capable. Single-factor authentication on a device code grant is meaningful — it indicates either no Conditional Access policy targeted the resource, or the policy excludes device code, or no MFA baseline exists. Treat SFA on these grants as elevated risk, not expected behavior.
- Missing `azure.signinlogs.properties.device_detail.*` fields indicate the authenticating endpoint is not Entra-joined, not Intune-enrolled, and not compliant — consistent with an attacker-controlled host completing the flow on the victim's behalf.
- Pivot on `azure.signinlogs.properties.correlation_id`, `session_id`, and `unique_token_identifier` to correlate with subsequent Microsoft Graph activity (`azure.graphactivitylogs-*`), Azure activity (`azure.activitylogs-*`), and M365 audit events (`o365.audit-*`) to map post-compromise actions on the same identity.
- Pivot on `azure.signinlogs.properties.user_id` against detection alerts on the same cluster to surface stacked alerts on the identity (rare app ID, rare authentication requirement, OAuth phishing first-party app, high-risk sign-in).
- Investigate `user_agent.original` for forged or anomalous tokens (offensive tooling like python-requests, httpx, fasthttp, kali, axiom, nuclei, msal-python, or deliberately silly forged UAs are high-confidence indicators). Real browsers in standard form are not exonerating but do reduce immediate priority.
- Inspect `source.as.organization.name` and `source.geo.country_iso_code` against the user's normal sign-in pattern. Sudden non-Microsoft hosting providers, residential VPNs, or unexpected geographies on these flows are high-priority.
- Microsoft-owned ASNs (MICROSOFT-CORP-MSN-AS-BLOCK / AS8075) are excluded by default but can be re-enabled for tenants where Azure-hosted infrastructure abuse is in scope.
- If results return zero rows, expand the lookback window or remove the resource_display_name filter to surface device code grants against unexpected resources.

## MITRE ATT&CK Techniques

- [T1078.004](https://attack.mitre.org/techniques/T1078/004)
- [T1528](https://attack.mitre.org/techniques/T1528)
- [T1566.002](https://attack.mitre.org/techniques/T1566/002)

## License

- `Elastic License v2`

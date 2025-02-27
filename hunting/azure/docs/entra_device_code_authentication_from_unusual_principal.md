# Azure Entra Device Code Authentication from Unusual Principal

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies Azure Entra sign-in logs where the authentication method used was Device Code Flow, which is often used for kiosk or IoT devices. If this authentication method is observed from a user or device that does not typically use it, it may indicate a potential compromise. This technique is common by adversaries conducting phishing campaigns with pre-registered device codes sent to targeted users whom are then redirected to Microsoft's device code authentication endpoint to initiation the workflow. The query filters for unusual authentication attempts based on the user principal name and the source address.

- **UUID:** `b54528ca-eec8-11ef-b314-f661ea17fbce`
- **Integration:** [azure](https://docs.elastic.co/integrations/azure)
- **Language:** `[ES|QL]`
- **Source File:** [Azure Entra Device Code Authentication from Unusual Principal](../queries/entra_device_code_authentication_from_unusual_principal.toml)

## Query

```sql
FROM logs-azure.signinlogs-*

// query Azure Entra Sign-in logs
| WHERE @timestamp > now() - 14 day
| WHERE event.dataset in ("azure.signinlogs")
    and event.category == "authentication"

    // filter for device code workflows
    // original transfer method indicates refresh tokens where device code was originally used
    and (
        azure.signinlogs.properties.authentication_protocol == "deviceCode" or
        azure.signinlogs.properties.original_transfer_method == "Device code flow"
    )

// bucket authentication attempts by each day
| EVAL target_time_window = DATE_TRUNC(1 days, @timestamp)

// aggregate authentication attempts by user principal name, source address, and message
| STATS
    auth_count = count(*) by
        target_time_window,
        azure.signinlogs.properties.user_principal_name,
        source.address,
        message

// filter further for low auth counts by a particular principal name
// indicating device code auth workflows are unusual for this user
| WHERE auth_count < 5
```

## Notes

- Review `azure.signinlogs.properties.authentication_protocol` to verify the authentication method used. Device Code Flow is typically reserved for IoT, kiosk, or embedded devices.
- Investigate `azure.signinlogs.properties.user_principal_name` to determine whether the user typically authenticates using Device Code Flow. Unusual use by regular accounts may indicate compromise.
- Analyze `source.as.organization.name` to determine if the request originated from a known hosting provider, VPN, or anonymization service that is unexpected in your environment.
- Examine `source.address` to check if the IP address is associated with previous suspicious activity, high-risk geolocations, or known threat infrastructure.
- Pivot on `azure.signinlogs.properties.original_transfer_method` to identify if the Device Code Flow was used in combination with refresh tokens, which may indicate session hijacking.
- Correlate findings with `azure.signinlogs.properties.authentication_processing_details` to identify possible legacy protocol usage, token replay, or bypass mechanisms.
- Review `azure.signinlogs.properties.applied_conditional_access_policies` to determine if Conditional Access rules were applied, bypassed, or enforced during authentication.
- Check `azure.signinlogs.properties.device_detail.browser` and `user_agent.original` to verify if the user agent aligns with expected authentication behavior for this user or device type.
- If authentication was successful, pivot on `azure.signinlogs.properties.user_principal_name` to check for additional high-risk activities within the same session.
- Monitor for multiple authentication attempts within a short period from different IPs or ASNs, which may indicate adversarial testing or phishing-based compromise.

## MITRE ATT&CK Techniques

- [T1078.004](https://attack.mitre.org/techniques/T1078/004)
- [T1528](https://attack.mitre.org/techniques/T1528)

## License

- `Elastic License v2`

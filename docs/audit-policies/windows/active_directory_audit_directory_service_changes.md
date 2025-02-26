## Setup

Certain rules in our ruleset require configuring audit policies to generate events when Active Directory objects are modified. These audit policies apply exclusively to Domain Controllers, as other servers do not produce events related to Active Directory object modifications.

To collect these logs using the [System Integration](https://www.elastic.co/guide/en/integrations/current/system.html), ensure that Security log collection is enabled in the integration configuration.

If your environment uses Windows Event Forwarding (WEF), configure the [Windows Integration](https://www.elastic.co/guide/en/integrations/current/windows.html) and ensure that Forwarded Events log collection is enabled.

### Enable Audit Policy via Group Policy

To enable `Audit Directory Service Changes` on all Domain Controllers via Group Policy, administrators must enable the `Audit Directory Service Changes` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration > 
Policies > 
Windows Settings > 
Security Settings > 
Advanced Audit Policies Configuration > 
Audit Policies > 
DS Access > 
**Audit Directory Service Changes (Success,Failure)**
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
```

### Additional Settings

The `Audit Directory Service Changes` policy does not cover all objects monitored by our detection rules. To address these gaps, in addition to enabling the audit policy, we must configure additional Access Control Entries (ACEs) using (Set-AuditRule)[https://github.com/OTRF/Set-AuditRule] to ensure proper monitoring.

Below is a list of the Audit Rules included in the ruleset. Modify them to match the Distinguished Names specific to your environment:

Audit changes on the MicrosoftDNS object:

```
Set-AuditRule -AdObjectPath 'AD:\\CN=MicrosoftDNS,DC=DomainDNSZones,DC=Domain,DC=com' -WellKnownSidType WorldSid -Rights CreateChild -InheritanceFlags Descendents -AttributeGUID e0fa1e8c-9b45-11d0-afdd-00c04fd930c9 -AuditFlags Success
```

Audit changes on the msDS-KeyCredentialLink attribute of User objects:

```
Set-AuditRule -AdObjectPath 'AD:\\CN=Users,DC=Domain,DC=com' -WellKnownSidType WorldSid -Rights WriteProperty -InheritanceFlags Children -AttributeGUID 5b47d60f-6090-40b2-9f37-2a4de88f3063 -AuditFlags Success
```

Audit changes on the servicePrincipalName attribute of User objects:

```
Set-AuditRule -AdObjectPath 'AD:\\CN=Users,DC=Domain,DC=com' -WellKnownSidType WorldSid -Rights WriteProperty -InheritanceFlags Children -AttributeGUID f3a64788-5306-11d1-a9c5-0000f80367c1 -AuditFlags Success
```

## Setup

Certain rules in our ruleset require monitoring user account management activities to detect unauthorized account creations, modifications, or deletions. Enabling this setting ensures visibility into critical account changes, helping maintain security and compliance by tracking administrative actions related to user accounts.

To collect these logs using the [System Integration](https://www.elastic.co/guide/en/integrations/current/system.html), ensure that Security log collection is enabled in the integration configuration.

If your environment uses Windows Event Forwarding (WEF), configure the [Windows Integration](https://www.elastic.co/guide/en/integrations/current/windows.html) and ensure that Forwarded Events log collection is enabled.

### Enable Audit Policy via Group Policy

To enable `Audit User Account Management` across a group of servers using Active Directory Group Policies, administrators must enable the `Audit User Account Management` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration > 
Policies > 
Windows Settings > 
Security Settings > 
Advanced Audit Policies Configuration > 
Audit Policies > 
Account Management > 
**Audit User Account Management (Success,Failure)**
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"User Account Management" /success:enable /failure:enable
```

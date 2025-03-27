## Setup

Certain rules in our ruleset require monitoring logon events to track user authentication attempts, detect unauthorized access, and investigate security incidents. Enabling this setting provides visibility into successful and failed logon attempts, helping strengthen security and compliance.

To collect these logs using the [System Integration](https://www.elastic.co/guide/en/integrations/current/system.html), ensure that Security log collection is enabled in the integration configuration.

If your environment uses Windows Event Forwarding (WEF), configure the [Windows Integration](https://www.elastic.co/guide/en/integrations/current/windows.html) and ensure that Forwarded Events log collection is enabled.

### Enable Audit Policy via Group Policy

To enable `Audit logon` events across a group of servers using Active Directory Group Policies, administrators must enable the `Audit logon` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration > 
Policies > 
Windows Settings > 
Security Settings > 
Advanced Audit Policies Configuration > 
Audit Policies > 
Logon/Logoff
**Audit Logon (Success,Failure)**
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"Logon" /success:enable /failure:enable
```

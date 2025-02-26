## Setup

Certain rules in our ruleset require monitoring special logon events to track privileged account usage. Special logon events indicate that an account with elevated privileges (such as administrators or service accounts) has logged in, helping detect unauthorized access or privilege escalation attempts.

To collect these logs using the [System Integration](https://www.elastic.co/guide/en/integrations/current/system.html), ensure that Security log collection is enabled in the integration configuration.

If your environment uses Windows Event Forwarding (WEF), configure the [Windows Integration](https://www.elastic.co/guide/en/integrations/current/windows.html) and ensure that Forwarded Events log collection is enabled.

### Enable Audit Policy via Group Policy

To enable `Audit Special Logon` across a group of servers using Active Directory Group Policies, administrators must enable the `Audit Special Logon` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration >  
Policies >  
Windows Settings >  
Security Settings >  
Advanced Audit Policies Configuration >  
Audit Policies >  
Logon/Logoff >  
**Audit Special Logon (Success)**
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol /set /subcategory:"TBD" /success:enable /failure:enable
```

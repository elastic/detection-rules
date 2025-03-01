## Setup

Certain rules in our ruleset require monitoring network connections managed by the Windows Filtering Platform (WFP) to detect unauthorized or suspicious network activity.

**Caution:** Enabling this audit policy generates a high volume of events.

To collect these logs using the [System Integration](https://www.elastic.co/guide/en/integrations/current/system.html), ensure that Security log collection is enabled in the integration configuration.

If your environment uses Windows Event Forwarding (WEF), configure the [Windows Integration](https://www.elastic.co/guide/en/integrations/current/windows.html) and ensure that Forwarded Events log collection is enabled.

### Enable Audit Policy via Group Policy

To enable `Audit Filtering Platform Connection` across a group of servers using Active Directory Group Policies, administrators must enable the `Audit Filtering Platform Connection` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration >
Windows Settings >
Security Settings >
Advanced Security Audit Policy Settings >
Audit Policies >
Object Access >
Audit Filtering Platform Connection (Success,Failure)
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

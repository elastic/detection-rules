## Setup

Certain rules in our ruleset require tracking changes to audit policies to detect unauthorized modifications or misconfigurations. Enabling this setting ensures visibility into audit policy changes, helping to maintain compliance and security.

To collect these logs using the [System Integration](https://www.elastic.co/guide/en/integrations/current/system.html), ensure that Security log collection is enabled in the integration configuration.

If your environment uses Windows Event Forwarding (WEF), configure the [Windows Integration](https://www.elastic.co/guide/en/integrations/current/windows.html) and ensure that Forwarded Events log collection is enabled.

### Enable Audit Policy via Group Policy

To enable `Audit Audit Policy Change` across a group of servers using Active Directory Group Policies, administrators must enable the `Audit Audit Policy Change` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration >
Windows Settings >
Security Settings >
Advanced Security Audit Policy Settings >
Audit Policies >
Policy Change >
**Audit Audit Policy Change (Success,Failure)**
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
```

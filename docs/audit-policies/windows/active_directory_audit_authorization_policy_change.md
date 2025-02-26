## Setup

Certain rules in our ruleset require monitoring changes to authorization policies to detect unauthorized modifications or misconfigurations. Enabling this setting ensures visibility into changes affecting user rights and security policies, helping maintain compliance and security.

To collect these logs using the [System Integration](https://www.elastic.co/guide/en/integrations/current/system.html), ensure that Security log collection is enabled in the integration configuration.

If your environment uses Windows Event Forwarding (WEF), configure the [Windows Integration](https://www.elastic.co/guide/en/integrations/current/windows.html) and ensure that Forwarded Events log collection is enabled.

### Enable Audit Policy via Group Policy

To enable `Audit Authorization Policy Change` across a group of servers using Active Directory Group Policies, administrators must enable the `Audit Authorization Policy Change` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration >
Windows Settings >
Security Settings >
Advanced Audit Policy Configuration >
Audit Policies >
Policy Change >
**Audit Authorization Policy Change (Success,Failure)**
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable
```

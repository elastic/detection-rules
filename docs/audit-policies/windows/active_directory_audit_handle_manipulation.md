## Setup

Certain rules in our ruleset require monitoring handle manipulation to detect unauthorized access attempts or suspicious interactions with system objects. Enabling this setting helps improve security visibility by tracking when handles to objects (such as files, registry keys, or processes) are opened or modified.

To collect these logs using the [System Integration](https://www.elastic.co/guide/en/integrations/current/system.html), ensure that Security log collection is enabled in the integration configuration.

If your environment uses Windows Event Forwarding (WEF), configure the [Windows Integration](https://www.elastic.co/guide/en/integrations/current/windows.html) and ensure that Forwarded Events log collection is enabled.

### Enable Audit Policy via Group Policy

To enable `Audit Handle Manipulation` across a group of servers using Active Directory Group Policies, administrators must enable the `Audit Handle Manipulation` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration >
Windows Settings >
Security Settings >
Advanced Audit Policy Configuration >
Audit Policies >
Object Access >
**Audit Handle Manipulation (Success,Failure)**
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
```

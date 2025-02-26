## Setup

Certain rules in our ruleset require monitoring token right adjustments to detect privilege changes in user sessions. Token right adjustments occur when a user's security token is modified to grant or revoke privileges, which can indicate privilege escalation attempts or administrative activity. Enabling this setting enhances visibility into security-sensitive changes affecting user privileges.

To collect these logs using the [System Integration](https://www.elastic.co/guide/en/integrations/current/system.html), ensure that Security log collection is enabled in the integration configuration.

If your environment uses Windows Event Forwarding (WEF), configure the [Windows Integration](https://www.elastic.co/guide/en/integrations/current/windows.html) and ensure that Forwarded Events log collection is enabled.

### Enable Audit Policy via Group Policy

To enable `Token Right Adjusted Events` across a group of servers using Active Directory Group Policies, administrators must enable the `Token Right Adjusted Events` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
Detailed Tracking >
Token Right Adjusted Events (Success)
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol /set /subcategory:"Token Right Adjusted Events" /success:enable /failure:enable
```

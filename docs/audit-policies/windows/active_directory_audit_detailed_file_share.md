## Setup

Certain rules in our ruleset require monitoring file share access to detect unauthorized access attempts or modifications. Enabling this setting helps improve security visibility and ensures compliance by tracking access to shared files and folders.

To collect these logs using the [System Integration](https://www.elastic.co/guide/en/integrations/current/system.html), ensure that Security log collection is enabled in the integration configuration.

If your environment uses Windows Event Forwarding (WEF), configure the [Windows Integration](https://www.elastic.co/guide/en/integrations/current/windows.html) and ensure that Forwarded Events log collection is enabled.

### Enable Audit Policy via Group Policy

To enable `Audit File Share` across a group of servers using Active Directory Group Policies, administrators must enable the `Audit File Share` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration > 
Policies > 
Windows Settings > 
Security Settings > 
Advanced Audit Policies Configuration > 
Audit Policies > 
Object Access > 
**Audit File Share (Success,Failure)**
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol /set /subcategory:"File Share" /success:enable /failure:disable
```

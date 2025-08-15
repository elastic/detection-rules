## Setup

Certain rules in our ruleset require monitoring security system extensions to detect unauthorized modifications, such as the installation of new system services, drivers, or security-related components. Enabling this setting helps ensure visibility into critical system changes that could impact security and system integrity.

To collect these logs using the [System Integration](https://www.elastic.co/guide/en/integrations/current/system.html), ensure that Security log collection is enabled in the integration configuration.

If your environment uses Windows Event Forwarding (WEF), configure the [Windows Integration](https://www.elastic.co/guide/en/integrations/current/windows.html) and ensure that Forwarded Events log collection is enabled.

### Enable Audit Policy via Group Policy

To enable `Audit Security System Extension` across a group of servers using Active Directory Group Policies, administrators must enable the `Audit Security System Extension` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration > 
Policies > 
Windows Settings > 
Security Settings > 
Advanced Audit Policies Configuration > 
Audit Policies > 
System > 
**Audit Security System Extension (Success)**
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"Security System Extension" /success:enable /failure:enable
```

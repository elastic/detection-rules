## Setup

Certain rules in our ruleset require configuring audit policies to generate events when Active Directory objects are accessed. These audit policies apply exclusively to Domain Controllers, as other servers do not produce events related to Active Directory object modifications.

To collect these logs using the [System Integration](https://www.elastic.co/guide/en/integrations/current/system.html), ensure that Security log collection is enabled in the integration configuration.

If your environment uses Windows Event Forwarding (WEF), configure the [Windows Integration](https://www.elastic.co/guide/en/integrations/current/windows.html) and ensure that Forwarded Events log collection is enabled.

### Enable Audit Policy via Group Policy

To enable `Audit Directory Service Access` on all Domain Controllers via Group Policy, administrators must enable the `Audit Directory Service Access` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration > 
Policies > 
Windows Settings > 
Security Settings > 
Advanced Audit Policies Configuration > 
Audit Policies > 
DS Access > 
**Audit Directory Service Access (Success,Failure)**
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"Directory Service Access" /success:enable /failure:enable
```

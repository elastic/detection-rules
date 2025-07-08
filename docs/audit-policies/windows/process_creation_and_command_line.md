## Setup

If leveraging process creation events from the Windows Security log for detections, enabling command line auditing for Windows Event ID 4688 (Process Creation) is required. When enabled, Windows records the full command line of newly created processes in the Security event log.

To collect these logs using the [System Integration](https://www.elastic.co/guide/en/integrations/current/system.html), ensure that Security log collection is enabled in the integration configuration.

If your environment uses Windows Event Forwarding (WEF), configure the [Windows Integration](https://www.elastic.co/guide/en/integrations/current/windows.html) and ensure that Forwarded Events log collection is enabled.

### Enable Audit Policy via Group Policy

To enable the record of command line in process creation events across a group of servers using Active Directory Group Policies, administrators must enable the `Include command line in process creation events` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration > 
Administrative Templates > 
System > 
Audit Process Creation >
**Include command line in process creation events (Enable)**
```

Additionally, confirm that the Audit Process Creation policy is enabled:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Configuration >
Detailed Tracking >
**Audit Process Creation (Success)**
```

### Enable Locally

To enable process creation and command line auditing on non-domain-joined servers, follow these steps with Administrative privileges:

1. Enable Process Creation Audit

Run the following command to enable auditing for process creation:
```
auditpol.exe /set /subcategory:"Process Creation" /success:enable /failure:enable
```


2. Enable Command Line Logging

Modify the registry to include command-line details in process creation logs:
```
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f  
```

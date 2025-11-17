# Audit Process Creation And Command Line

## Setup

If leveraging process creation events from the Windows Security log for detections, enabling command line auditing for Windows Event ID 4688 (Process Creation) is required. When enabled, Windows records the full command line of newly created processes in the Security event log.

### Enable Audit Policy via Group Policy

To enable the record of command line in process creation events across a group of servers using Active Directory Group Policies, administrators must enable the `Include command line in process creation events` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration >
Administrative Templates >
System >
Audit Process Creation >
Include command line in process creation events (Enable)
```

Additionally, confirm that the Audit Process Creation policy is enabled:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Configuration >
Detailed Tracking >
Audit Process Creation (Success)
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

## Event IDs

When this audit policy is enabled, the following event IDs may be generated:

* **4688**: A new process has been created.
* **4696**: A primary token was assigned to process.

## Related Rules

Use the following GitHub search to identify rules that use the events listed:

[Elastic Detection Rules Github Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Windows+Security+Event+Logs%22+AND+%28%224688%22+OR+%22created-process%22+OR+%224696%22+OR+%22process+where%22+OR+%22event.category%3Aprocess%22%29++language%3ATOML&type=code)

## Setup

Certain rules in our ruleset require enabling PowerShell Script Block Logging to record the content of processed script blocks in the Windows Event Log.

To collect these logs using the [Windows Integration](https://www.elastic.co/docs/current/integrations/windows), select the `Powershell Operational` channel on the integration setup page.

### Enable Audit Policy via Group Policy

To enable PowerShell Script Block logging across a group of servers using Active Directory Group Policies, administrators must enable the `Turn on PowerShell Script Block Logging` policy. Follow these steps to implement the logging policy through `Advanced Audit Configuration`:

```
Computer Configuration >
Administrative Templates >
Windows PowerShell >
**Turn on PowerShell Script Block Logging (Enable)**
```

### Enable Audit Policy via Registry

To configure the audit on servers that aren't domain joined, the EnableScriptBlockLogging registry key must be set to 1. Here is an example modification command:

```
reg add "hklm\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1
```

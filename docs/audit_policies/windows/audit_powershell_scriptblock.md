# Audit Powershell Scriptblock

## Setup

Some detection rules require enabling PowerShell Script Block Logging to record the content of processed script blocks in the Windows Event Log.

To collect these logs, use the [Windows Integration](https://www.elastic.co/docs/current/integrations/windows) and select the `Powershell Operational` channel on the integration setup page.

### Enable Audit Policy via Group Policy

To enable PowerShell Script Block logging across a group of servers using Active Directory Group Policies, administrators must enable the `Turn on PowerShell Script Block Logging` policy. Follow these steps to implement the logging policy:

```
Computer Configuration >
Administrative Templates >
Windows PowerShell >
Turn on PowerShell Script Block Logging (Enable)
```

### Enable Audit Policy via Registry

To configure the audit on servers that aren't domain joined, the EnableScriptBlockLogging registry key must be set to 1. Here is an example modification command:

```
reg add "hklm\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1
```

## Event IDs

When this audit policy is enabled, the following event IDs may be generated in the `Microsoft-Windows-PowerShell/Operational` log:

* **4104**: Script block execution.

## Related Rules

Use the following GitHub search to identify rules that use the events listed:

[Elastic Detection Rules Github Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22PowerShell+Logs%22+AND+%28%224104%22+OR+%22powershell.file.script_block_text%22%29++language%3ATOML&type=code)

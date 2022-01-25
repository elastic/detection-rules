# Alerts generation from detection rules

This report captures the detection rules signals generation coverage. Here you can
learn what rules are supported and what not and why.

Reasons for rules being not supported:
* rule type is not EQL or query (e.g. ML, threshold)
* query language is not EQL or Kuery (e.g. Lucene)
* fields type mismatch (i.e. non-ECS field with incorrect type definition)
* incorrect document generation

Curious about the inner workings? Read [here](signals_generation.md).

## Table of contents
   1. [Failed rules](#failed-rules)
   1. [Rules with too few signals](#rules-with-too-few-signals)

## Failed rules

### Account Password Reset Remotely

```python
sequence by host.id with maxspan=5m
  [authentication where event.action == "logged-in" and
    /* event 4624 need to be logged */
    winlog.logon.type : "Network" and event.outcome == "success" and source.ip != null and
    not source.ip in ("127.0.0.1", "::1")] by winlog.event_data.TargetLogonId
   /* event 4724 need to be logged */
  [iam where event.action == "reset-password"] by winlog.event_data.SubjectLogonId
```

```python
[{'event': {'action': 'logged-in', 'outcome': 'success', 'category': ['authentication']}, 'winlog': {'logon': {'type': 'Network'}, 'event_data': {'TargetLogonId': 'yFj'}}, 'source': {'ip': 'aa79:ec58:8d14:2981:f18d:f2a6:6b1f:4182'}, 'host': {'id': 'fUy'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}},
{'event': {'action': 'reset-password', 'category': ['iam']}, 'host': {'id': 'fUy'}, 'winlog': {'event_data': {'SubjectLogonId': 'yFj'}}, '@timestamp': 1, 'ecs': {'version': '1.12.1'}}]
```



SDE says:
> An error occurred during rule execution: message: "verification_exception: [verification_exception] Reason: Found 1 problem
line 5:9: 1st argument of [source.ip in ("127.0.0.1", "::1")] must be [ip], found value ["127.0.0.1"] type [keyword]" name: "Account Password Reset Remotely" id: "<i>&lt;redacted&gt;</i>" rule id: "2820c9c2-bcd7-4d6e-9eba-faf3891ba450" signals index: ".siem-signals-default"

### Apple Scripting Execution with Administrator Privileges

```python
process where event.type in ("start", "process_started") and process.name : "osascript" and
  process.command_line : "osascript*with administrator privileges"
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Apple Scripting Execution with Administrator Privileges" id: "<i>&lt;redacted&gt;</i>" rule id: "827f8d8f-4117-4ae4-b551-f56d54b9da6b" signals index: ".siem-signals-default"

### Attempt to Mount SMB Share via Command Line

```python
process where event.type in ("start", "process_started") and
  (
    process.name : "mount_smbfs" or
    (process.name : "open" and process.args : "smb://*") or
    (process.name : "mount" and process.args : "smbfs") or
    (process.name : "osascript" and process.command_line : "osascript*mount volume*smb://*")
  )
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'mount_smbfs'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



SDE says:
> An error occurred during rule execution: message: "verification_exception: [verification_exception] Reason: Found 1 problem
line 6:37: Unknown column [process.command_line], did you mean any of [process.working_directory, process.entity_id, process.executable, process.name, process.parent.name, process.parent.pid]?" name: "Attempt to Mount SMB Share via Command Line" id: "<i>&lt;redacted&gt;</i>" rule id: "661545b4-1a90-4f45-85ce-2ebd7c6a15d0" signals index: ".siem-signals-default"

### Attempt to Remove File Quarantine Attribute

```python
process where event.type in ("start", "process_started") and
  process.args : "xattr" and
  (
    (process.args : "com.apple.quarantine" and process.args : ("-d", "-w")) or
    (process.args : "-c" and process.command_line :
      (
        "/bin/bash -c xattr -c *",
        "/bin/zsh -c xattr -c *",
        "/bin/sh -c xattr -c *"
      )
    )
  )
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'args': ['xattr', 'com.apple.quarantine', '-d', '-w']}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



SDE says:
> An error occurred during rule execution: message: "verification_exception: [verification_exception] Reason: Found 1 problem
line 5:30: Unknown column [process.command_line], did you mean any of [process.working_directory, process.entity_id, process.executable, process.name, process.parent.name, process.parent.pid]?" name: "Attempt to Remove File Quarantine Attribute" id: "<i>&lt;redacted&gt;</i>" rule id: "f0b48bbc-549e-4bcf-8ee0-a7a72586c6a7" signals index: ".siem-signals-default"

### Azure Virtual Network Device Modified or Deleted

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:("MICROSOFT.NETWORK/NETWORKINTERFACES/TAPCONFIGURATIONS/WRITE" or
"MICROSOFT.NETWORK/NETWORKINTERFACES/TAPCONFIGURATIONS/DELETE" or "MICROSOFT.NETWORK/NETWORKINTERFACES/WRITE" or
"MICROSOFT.NETWORK/NETWORKINTERFACES/JOIN/ACTION" or "MICROSOFT.NETWORK/NETWORKINTERFACES/DELETE"or
"MICROSOFT.NETWORK/NETWORKVIRTUALAPPLIANCES/DELETE" or "MICROSOFT.NETWORK/NETWORKVIRTUALAPPLIANCES/WRITE" or
"MICROSOFT.NETWORK/VIRTUALHUBS/DELETE" or "MICROSOFT.NETWORK/VIRTUALHUBS/WRITE" or
"MICROSOFT.NETWORK/VIRTUALROUTERS/WRITE" or "MICROSOFT.NETWORK/VIRTUALROUTERS/DELETE") and 
event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKINTERFACES/TAPCONFIGURATIONS/WRITE'}}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



SDE says:
> An error occurred during rule execution: message: "Expected ")", AND, OR, whitespace but "o" found.
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:("MICROSOFT.NETWORK/NETWORKINTERFACES/TAPCONFIGURATIONS/WRITE" or
"MICROSOFT.NETWORK/NETWORKINTERFACES/TAPCONFIGURATIONS/DELETE" or "MICROSOFT.NETWORK/NETWORKINTERFACES/WRITE" or
"MICROSOFT.NETWORK/NETWORKINTERFACES/JOIN/ACTION" or "MICROSOFT.NETWORK/NETWORKINTERFACES/DELETE"or
"MICROSOFT.NETWORK/NETWORKVIRTUALAPPLIANCES/DELETE" or "MICROSOFT.NETWORK/NETWORKVIRTUALAPPLIANCES/WRITE" or
"MICROSOFT.NETWORK/VIRTUALHUBS/DELETE" or "MICROSOFT.NETWORK/VIRTUALHUBS/WRITE" or
"MICROSOFT.NETWORK/VIRTUALROUTERS/WRITE" or "MICROSOFT.NETWORK/VIRTUALROUTERS/DELETE") and 
event.outcome:(Success or success)

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------^" name: "Azure Virtual Network Device Modified or Deleted" id: "<i>&lt;redacted&gt;</i>" rule id: "573f6e7a-7acf-4bcd-ad42-c4969124d3c0" signals index: ".siem-signals-default"

### Command Shell Activity Started via RunDLL32

```python
process where event.type == "start" and
 process.name : ("cmd.exe", "powershell.exe") and
  process.parent.name : "rundll32.exe" and process.parent.command_line != null and
  /* common FPs can be added here */
  not process.parent.args : ("C:\\Windows\\System32\\SHELL32.dll,RunAsNewUser_RunDLL",
                             "C:\\WINDOWS\\*.tmp,zzzzInvokeManagedCustomActionOutOfProc")
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Command Shell Activity Started via RunDLL32" id: "<i>&lt;redacted&gt;</i>" rule id: "9ccf3ce0-0057-440a-91f5-870c6ad39093" signals index: ".siem-signals-default"

### Component Object Model Hijacking

```python
registry where
 /* uncomment once length is stable length(bytes_written_string) > 0 and */
 (registry.path : "HK*}\\InprocServer32\\" and registry.data.strings: ("scrobj.dll", "C:\\*\\scrobj.dll") and
 not registry.path : "*\\{06290BD*-48AA-11D2-8432-006008C3FBFC}\\*") 
 or
 /* in general COM Registry changes on Users Hive is less noisy and worth alerting */
 (registry.path : ("HKEY_USERS\\*Classes\\*\\InprocServer32\\",
                   "HKEY_USERS\\*Classes\\*\\LocalServer32\\",
                   "HKEY_USERS\\*Classes\\*\\DelegateExecute\\", 
                   "HKEY_USERS\\*Classes\\*\\TreatAs\\", 
                   "HKEY_USERS\\*Classes\\CLSID\\*\\ScriptletURL\\") and
 not (process.executable : "?:\\Program Files*\\Veeam\\Backup and Replication\\Console\\veeam.backup.shell.exe" and
      registry.path : "HKEY_USERS\\S-1-5-21-*_Classes\\CLSID\\*\\LocalServer32\\") and
 /* not necessary but good for filtering privileged installations */
 user.domain != "NT AUTHORITY")
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Component Object Model Hijacking" id: "<i>&lt;redacted&gt;</i>" rule id: "16a52c14-7883-47af-8745-9357803f0d4c" signals index: ".siem-signals-default"

### Control Panel Process with Unusual Arguments

```python
process where event.type in ("start", "process_started") and
 process.executable : ("?:\\Windows\\SysWOW64\\control.exe", "?:\\Windows\\System32\\control.exe") and
 process.command_line :
          ("*.jpg*",
           "*.png*",
           "*.gif*",
           "*.bmp*",
           "*.jpeg*",
           "*.TIFF*",
           "*.inf*",
           "*.dat*",
           "*.cpl:*/*",
           "*../../..*",
           "*/AppData/Local/*",
           "*:\\Users\\Public\\*",
           "*\\AppData\\Local\\*")
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Control Panel Process with Unusual Arguments" id: "<i>&lt;redacted&gt;</i>" rule id: "416697ae-e468-4093-a93d-59661fa619ec" signals index: ".siem-signals-default"

### Creation of Hidden Files and Directories

```python
process where event.type in ("start", "process_started") and
  process.working_directory in ("/tmp", "/var/tmp", "/dev/shm") and
  process.args regex~ """\.[a-z0-9_\-][a-z0-9_\-\.]{1,254}""" and
  not process.name in ("ls", "find")
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Creation of Hidden Files and Directories" id: "<i>&lt;redacted&gt;</i>" rule id: "b9666521-4742-49ce-9ddc-b8e84c35acae" signals index: ".siem-signals-default"

### Creation of Hidden Login Item via Apple Script

```python
process where event.type in ("start", "process_started") and process.name : "osascript" and
 process.command_line : "osascript*login item*hidden:true*"
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Creation of Hidden Login Item via Apple Script" id: "<i>&lt;redacted&gt;</i>" rule id: "f24bcae1-8980-4b30-b5dd-f851b055c9e7" signals index: ".siem-signals-default"

### DNS-over-HTTPS Enabled via Registry

```python
registry where event.type in ("creation", "change") and
  (registry.path : "*\\SOFTWARE\\Policies\\Microsoft\\Edge\\BuiltInDnsClientEnabled" and
  registry.data.strings : "1") or
  (registry.path : "*\\SOFTWARE\\Google\\Chrome\\DnsOverHttpsMode" and
  registry.data.strings : "secure") or
  (registry.path : "*\\SOFTWARE\\Policies\\Mozilla\\Firefox\\DNSOverHTTPS" and
  registry.data.strings : "1")
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "DNS-over-HTTPS Enabled via Registry" id: "<i>&lt;redacted&gt;</i>" rule id: "a22a09c2-2162-4df0-a356-9aacbeb56a04" signals index: ".siem-signals-default"

### Disabling User Account Control via Registry Modification

```python
registry where event.type == "change" and
  registry.path :
    (
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA",
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin",
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\PromptOnSecureDesktop"
    ) and
  registry.data.strings : "0"
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Disabling User Account Control via Registry Modification" id: "<i>&lt;redacted&gt;</i>" rule id: "d31f183a-e5b1-451b-8534-ba62bca0b404" signals index: ".siem-signals-default"

### Encoded Executable Stored in the Registry

```python
registry where
/* update here with encoding combinations */
 registry.data.strings : "TVqQAAMAAAAEAAAA*"
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Encoded Executable Stored in the Registry" id: "<i>&lt;redacted&gt;</i>" rule id: "93c1ce76-494c-4f01-8167-35edfb52f7b1" signals index: ".siem-signals-default"

### Executable File Creation with Multiple Extensions

```python
file where event.type == "creation" and file.extension : "exe" and
  file.name regex~ """.*\.(vbs|vbe|bat|js|cmd|wsh|ps1|pdf|docx?|xlsx?|pptx?|txt|rtf|gif|jpg|png|bmp|hta|txt|img|iso)\.exe"""
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Executable File Creation with Multiple Extensions" id: "<i>&lt;redacted&gt;</i>" rule id: "8b2b3a62-a598-4293-bc14-3d5fa22bb98f" signals index: ".siem-signals-default"

### Execution from Unusual Directory - Command Line

```python
process where event.type in ("start", "process_started", "info") and
  process.name : ("wscript.exe", 
                  "cscript.exe", 
                  "rundll32.exe", 
                  "regsvr32.exe", 
                  "cmstp.exe",
                  "RegAsm.exe",
                  "installutil.exe",
                  "mshta.exe",
                  "RegSvcs.exe", 
                  "powershell.exe", 
                  "pwsh.exe", 
                  "cmd.exe") and

  /* add suspicious execution paths here */
  process.args : ("C:\\PerfLogs\\*",
                  "C:\\Users\\Public\\*",
                  "C:\\Users\\Default\\*",
                  "C:\\Windows\\Tasks\\*",
                  "C:\\Intel\\*", 
                  "C:\\AMD\\Temp\\*", 
                  "C:\\Windows\\AppReadiness\\*", 
                  "C:\\Windows\\ServiceState\\*",
                  "C:\\Windows\\security\\*",
                  "C:\\Windows\\IdentityCRL\\*",
                  "C:\\Windows\\Branding\\*",
                  "C:\\Windows\\csc\\*",
                  "C:\\Windows\\DigitalLocker\\*",
                  "C:\\Windows\\en-US\\*",
                  "C:\\Windows\\wlansvc\\*",
                  "C:\\Windows\\Prefetch\\*",
                  "C:\\Windows\\Fonts\\*",
                  "C:\\Windows\\diagnostics\\*",
                  "C:\\Windows\\TAPI\\*",
                  "C:\\Windows\\INF\\*",
                  "C:\\Windows\\System32\\Speech\\*",
                  "C:\\windows\\tracing\\*",
                  "c:\\windows\\IME\\*",
                  "c:\\Windows\\Performance\\*",
                  "c:\\windows\\intel\\*",
                  "c:\\windows\\ms\\*",
                  "C:\\Windows\\dot3svc\\*",
                  "C:\\Windows\\ServiceProfiles\\*",
                  "C:\\Windows\\panther\\*",
                  "C:\\Windows\\RemotePackages\\*",
                  "C:\\Windows\\OCR\\*",
                  "C:\\Windows\\appcompat\\*",
                  "C:\\Windows\\apppatch\\*",
                  "C:\\Windows\\addins\\*",
                  "C:\\Windows\\Setup\\*",
                  "C:\\Windows\\Help\\*",
                  "C:\\Windows\\SKB\\*",
                  "C:\\Windows\\Vss\\*",
                  "C:\\Windows\\Web\\*",
                  "C:\\Windows\\servicing\\*",
                  "C:\\Windows\\CbsTemp\\*",
                  "C:\\Windows\\Logs\\*",
                  "C:\\Windows\\WaaS\\*",
                  "C:\\Windows\\twain_32\\*",
                  "C:\\Windows\\ShellExperiences\\*",
                  "C:\\Windows\\ShellComponents\\*",
                  "C:\\Windows\\PLA\\*",
                  "C:\\Windows\\Migration\\*",
                  "C:\\Windows\\debug\\*",
                  "C:\\Windows\\Cursors\\*",
                  "C:\\Windows\\Containers\\*",
                  "C:\\Windows\\Boot\\*",
                  "C:\\Windows\\bcastdvr\\*",
                  "C:\\Windows\\assembly\\*",
                  "C:\\Windows\\TextInput\\*",
                  "C:\\Windows\\security\\*",
                  "C:\\Windows\\schemas\\*",
                  "C:\\Windows\\SchCache\\*",
                  "C:\\Windows\\Resources\\*",
                  "C:\\Windows\\rescache\\*",
                  "C:\\Windows\\Provisioning\\*",
                  "C:\\Windows\\PrintDialog\\*",
                  "C:\\Windows\\PolicyDefinitions\\*",
                  "C:\\Windows\\media\\*",
                  "C:\\Windows\\Globalization\\*",
                  "C:\\Windows\\L2Schemas\\*",
                  "C:\\Windows\\LiveKernelReports\\*",
                  "C:\\Windows\\ModemLogs\\*",
                  "C:\\Windows\\ImmersiveControlPanel\\*",
                  "C:\\$Recycle.Bin\\*") and
  not process.parent.executable : ("C:\\WINDOWS\\System32\\DriverStore\\FileRepository\\*\\igfxCUIService*.exe",
                                   "C:\\Windows\\System32\\spacedeskService.exe",
                                   "C:\\Program Files\\Dell\\SupportAssistAgent\\SRE\\SRE.exe") and
  not (process.name : "rundll32.exe" and process.args : ("uxtheme.dll,#64", "PRINTUI.DLL,PrintUIEntry"))
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Execution from Unusual Directory - Command Line" id: "<i>&lt;redacted&gt;</i>" rule id: "cff92c41-2225-4763-b4ce-6f71e5bda5e6" signals index: ".siem-signals-default"

### Image File Execution Options Injection

```python
registry where length(registry.data.strings) > 0 and
 registry.path : ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*.exe\\Debugger", 
                  "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*\\Debugger", 
                  "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*\\MonitorProcess", 
                  "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*\\MonitorProcess") and
   /* add FPs here */
 not registry.data.strings regex~ ("""C:\\Program Files( \(x86\))?\\ThinKiosk\\thinkiosk\.exe""", """.*\\PSAppDeployToolkit\\.*""")
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Image File Execution Options Injection" id: "<i>&lt;redacted&gt;</i>" rule id: "6839c821-011d-43bd-bd5b-acff00257226" signals index: ".siem-signals-default"

### Modification of AmsiEnable Registry Key

```python
registry where event.type in ("creation", "change") and
  registry.path: "HKEY_USERS\\*\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable" and
  registry.data.strings: "0"
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Modification of AmsiEnable Registry Key" id: "<i>&lt;redacted&gt;</i>" rule id: "f874315d-5188-4b4a-8521-d1c73093a7e4" signals index: ".siem-signals-default"

### Modification of WDigest Security Provider

```python
registry where event.type in ("creation", "change") and
  registry.path:"HKLM\\SYSTEM\\*ControlSet*\\Control\\SecurityProviders\\WDigest\\UseLogonCredential" and
  registry.data.strings:"1"
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Modification of WDigest Security Provider" id: "<i>&lt;redacted&gt;</i>" rule id: "d703a5af-d5b0-43bd-8ddb-7a5d500b7da5" signals index: ".siem-signals-default"

### Network Logon Provider Registry Modification

```python
registry where registry.data.strings != null and
 registry.path : "HKLM\\SYSTEM\\*ControlSet*\\Services\\*\\NetworkProvider\\ProviderPath" and
 /* Excluding default NetworkProviders RDPNP, LanmanWorkstation and webclient. */
 not ( user.id : "S-1-5-18" and
       registry.data.strings in
                ("%SystemRoot%\\System32\\ntlanman.dll",
                 "%SystemRoot%\\System32\\drprov.dll",
                 "%SystemRoot%\\System32\\davclnt.dll")
      )
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Network Logon Provider Registry Modification" id: "<i>&lt;redacted&gt;</i>" rule id: "54c3d186-0461-4dc3-9b33-2dc5c7473936" signals index: ".siem-signals-default"

### NullSessionPipe Registry Modification

```python
registry where
registry.path : "HKLM\\SYSTEM\\*ControlSet*\\services\\LanmanServer\\Parameters\\NullSessionPipes" and
registry.data.strings != null
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "NullSessionPipe Registry Modification" id: "<i>&lt;redacted&gt;</i>" rule id: "ddab1f5f-7089-44f5-9fda-de5b11322e77" signals index: ".siem-signals-default"

### Persistence via Login or Logout Hook

```python
process where event.type == "start" and
 process.name == "defaults" and process.args == "write" and process.args in ("LoginHook", "LogoutHook") and
 not process.args :
       (
         "Support/JAMF/ManagementFrameworkScripts/logouthook.sh",
         "Support/JAMF/ManagementFrameworkScripts/loginhook.sh",
         "/Library/Application Support/JAMF/ManagementFrameworkScripts/logouthook.sh",
         "/Library/Application Support/JAMF/ManagementFrameworkScripts/loginhook.sh"
       )
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Persistence via Login or Logout Hook" id: "<i>&lt;redacted&gt;</i>" rule id: "5d0265bf-dea9-41a9-92ad-48a8dcd05080" signals index: ".siem-signals-default"

### Persistence via WMI Standard Registry Provider

```python
registry where 
 registry.data.strings != null and process.name : "WmiPrvSe.exe" and
 registry.path : (
                  "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
                  "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
                  "HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
                  "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*",
                  "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*",
                  "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*",
                  "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\*",
                  "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*",
                  "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\*",
                  "HKLM\\SYSTEM\\*ControlSet*\\Services\\*\\ServiceDLL",
                  "HKLM\\SYSTEM\\*ControlSet*\\Services\\*\\ImagePath",
                  "HKEY_USERS\\*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\\*", 
                  "HKEY_USERS\\*\\Environment\\UserInitMprLogonScript", 
                  "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Load", 
                  "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell", 
                  "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Shell", 
                  "HKEY_USERS\\*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logoff\\Script", 
                  "HKEY_USERS\\*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logon\\Script", 
                  "HKEY_USERS\\*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Shutdown\\Script", 
                  "HKEY_USERS\\*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Startup\\Script", 
                  "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Ctf\\LangBarAddin\\*\\FilePath", 
                  "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Internet Explorer\\Extensions\\*\\Exec", 
                  "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Internet Explorer\\Extensions\\*\\Script", 
                  "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Command Processor\\Autorun"
                  )
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Persistence via WMI Standard Registry Provider" id: "<i>&lt;redacted&gt;</i>" rule id: "70d12c9c-0dbd-4a1a-bc44-1467502c9cf6" signals index: ".siem-signals-default"

### Potential Credential Access via Renamed COM+ Services DLL

```python
sequence by process.entity_id with maxspan=1m
 [process where event.category == "process" and
    process.name : "rundll32.exe"]
 [process where event.category == "process" and event.dataset : "windows.sysmon_operational" and event.code == "7" and
   (file.pe.original_file_name : "COMSVCS.DLL" or file.pe.imphash : "EADBCCBB324829ACB5F2BBE87E5549A8") and
    /* renamed COMSVCS */
    not file.name : "COMSVCS.DLL"]
```

```python
[{'event': {'category': ['process', 'process']}, 'process': {'name': 'rundll32.exe', 'entity_id': 'ZFy'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}},
{'event': {'category': ['process', 'process'], 'dataset': 'windows.sysmon_operational', 'code': '7'}, 'file': {'pe': {'original_file_name': 'COMSVCS.DLL'}, 'name': 'XIU'}, 'process': {'entity_id': 'ZFy'}, '@timestamp': 1, 'ecs': {'version': '1.12.1'}}]
```



SDE says:
> An error occurred during rule execution: message: "verification_exception: [verification_exception] Reason: Found 1 problem
line 5:51: Unknown column [file.pe.imphash], did you mean [file.path]?" name: "Potential Credential Access via Renamed COM+ Services DLL" id: "<i>&lt;redacted&gt;</i>" rule id: "c5c9f591-d111-4cf8-baec-c26a39bc31ef" signals index: ".siem-signals-default"

### Potential Credential Access via Windows Utilities

```python
process where event.type in ("start", "process_started") and
/* update here with any new lolbas with dump capability */
(process.pe.original_file_name == "procdump" and process.args : "-ma") or
(process.name : "ProcessDump.exe" and not process.parent.executable regex~ """C:\\Program Files( \(x86\))?\\Cisco Systems\\.*""") or
(process.pe.original_file_name == "WriteMiniDump.exe" and not process.parent.executable regex~ """C:\\Program Files( \(x86\))?\\Steam\\.*""") or
(process.pe.original_file_name == "RUNDLL32.EXE" and (process.args : "MiniDump*" or process.command_line : "*comsvcs.dll*#24*")) or
(process.pe.original_file_name == "RdrLeakDiag.exe" and process.args : "/fullmemdmp") or
(process.pe.original_file_name == "SqlDumper.exe" and process.args : "0x01100*") or
(process.pe.original_file_name == "TTTracer.exe" and process.args : "-dumpFull" and process.args : "-attach") or
(process.pe.original_file_name == "ntdsutil.exe" and process.args : "create*full*") or
(process.pe.original_file_name == "diskshadow.exe" and process.args : "/s")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'procdump'}, 'args': ['-ma']}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



SDE says:
> An error occurred during rule execution: message: "verification_exception: [verification_exception] Reason: Found 1 problem
line 6:85: Unknown column [process.command_line], did you mean any of [process.working_directory, process.entity_id, process.executable, process.name, process.parent.name, process.parent.pid]?" name: "Potential Credential Access via Windows Utilities" id: "<i>&lt;redacted&gt;</i>" rule id: "00140285-b827-4aee-aa09-8113f58a08f3" signals index: ".siem-signals-default"

### Potential Persistence via Time Provider Modification

```python
registry where event.type:"change" and
  registry.path:"HKLM\\SYSTEM\\*ControlSet*\\Services\\W32Time\\TimeProviders\\*" and
  registry.data.strings:"*.dll"
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Potential Persistence via Time Provider Modification" id: "<i>&lt;redacted&gt;</i>" rule id: "14ed1aa9-ebfd-4cf9-a463-0ac59ec55204" signals index: ".siem-signals-default"

### Potential Port Monitor or Print Processor Registration Abuse

```python
registry where event.type in ("creation", "change") and
  registry.path : ("HKLM\\SYSTEM\\*ControlSet*\\Control\\Print\\Monitors\\*",
    "HLLM\\SYSTEM\\*ControlSet*\\Control\\Print\\Environments\\Windows*\\Print Processors\\*") and
  registry.data.strings : "*.dll" and
  /* exclude SYSTEM SID - look for changes by non-SYSTEM user */
  not user.id : "S-1-5-18"
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Potential Port Monitor or Print Processor Registration Abuse" id: "<i>&lt;redacted&gt;</i>" rule id: "8f3e91c7-d791-4704-80a1-42c160d7aa27" signals index: ".siem-signals-default"

### Potential PrintNightmare Exploit Registry Modification

```python
/* This rule is not compatible with Sysmon due to schema issues */

registry where process.name : "spoolsv.exe" and
  (registry.path : "HKLM\\SYSTEM\\ControlSet*\\Control\\Print\\Environments\\Windows*\\Drivers\\Version-3\\mimikatz*\\Data File" or
  (registry.path : "HKLM\\SYSTEM\\ControlSet*\\Control\\Print\\Environments\\Windows*\\Drivers\\Version-3\\*\\Configuration File" and
   registry.data.strings : ("kernelbase.dll", "ntdll.dll", "kernel32.dll", "winhttp.dll", "user32.dll")))
```

```python
[{'process': {'name': 'spoolsv.exe'}, 'registry': {'path': 'hklm\\system\\controlsetxiutknioixtfl\\control\\print\\environments\\windowshmxbnleoaagaifq\\drivers\\version-3\\mimikatzeewvpymgznf\\data file'}, 'event': {'category': ['registry']}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



SDE says:
> An error occurred during rule execution: message: "verification_exception: [verification_exception] Reason: Found 1 problem
line 6:4: Unknown column [registry.data.strings], did you mean [registry.path]?" name: "Potential PrintNightmare Exploit Registry Modification" id: "<i>&lt;redacted&gt;</i>" rule id: "6506c9fd-229e-4722-8f0f-69be759afd2a" signals index: ".siem-signals-default"

### Potential Privacy Control Bypass via Localhost Secure Copy

```python
process where event.type in ("start", "process_started") and 
 process.name:"scp" and
 process.args:"StrictHostKeyChecking=no" and 
 process.command_line:("scp *localhost:/*", "scp *127.0.0.1:/*") and
 not process.args:"vagrant@*127.0.0.1*"
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Potential Privacy Control Bypass via Localhost Secure Copy" id: "<i>&lt;redacted&gt;</i>" rule id: "c02c8b9f-5e1d-463c-a1b0-04edcdfe1a3d" signals index: ".siem-signals-default"

### Potential SharpRDP Behavior

```python
/* Incoming RDP followed by a new RunMRU string value set to cmd, powershell, taskmgr or tsclient, followed by process execution within 1m */

sequence by host.id with maxspan=1m
  [network where event.type == "start" and process.name : "svchost.exe" and destination.port == 3389 and 
   network.direction : ("incoming", "ingress") and network.transport == "tcp" and
   source.address != "127.0.0.1" and source.address != "::1"
  ]

  [registry where process.name : "explorer.exe" and 
   registry.path : ("HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\\*") and
   registry.data.strings : ("cmd.exe*", "powershell.exe*", "taskmgr*", "\\\\tsclient\\*.exe\\*")
  ]

  [process where event.type in ("start", "process_started") and
   (process.parent.name : ("cmd.exe", "powershell.exe", "taskmgr.exe") or process.args : ("\\\\tsclient\\*.exe")) and 
   not process.name : "conhost.exe"
   ]
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Potential SharpRDP Behavior" id: "<i>&lt;redacted&gt;</i>" rule id: "8c81e506-6e82-4884-9b9a-75d3d252f967" signals index: ".siem-signals-default"

### Privilege Escalation via Windir Environment Variable

```python
registry where registry.path : ("HKEY_USERS\\*\\Environment\\windir", "HKEY_USERS\\*\\Environment\\systemroot") and 
 not registry.data.strings : ("C:\\windows", "%SystemRoot%")
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Privilege Escalation via Windir Environment Variable" id: "<i>&lt;redacted&gt;</i>" rule id: "d563aaba-2e72-462b-8658-3e5ea22db3a6" signals index: ".siem-signals-default"

### Prompt for Credentials with OSASCRIPT

```python
process where event.type in ("start", "process_started") and process.name : "osascript" and
 process.command_line : "osascript*display dialog*password*"
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Prompt for Credentials with OSASCRIPT" id: "<i>&lt;redacted&gt;</i>" rule id: "38948d29-3d5d-42e3-8aec-be832aaaf8eb" signals index: ".siem-signals-default"

### RDP Enabled via Registry

```python
registry where
registry.path : "HKLM\\SYSTEM\\ControlSet*\\Control\\Terminal Server\\fDenyTSConnections" and
registry.data.strings == "0" and not (process.name : "svchost.exe" and user.domain == "NT AUTHORITY") and
not process.executable : "C:\\Windows\\System32\\SystemPropertiesRemote.exe"
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "RDP Enabled via Registry" id: "<i>&lt;redacted&gt;</i>" rule id: "58aa72ca-d968-4f34-b9f7-bea51d75eb50" signals index: ".siem-signals-default"

### SIP Provider Modification

```python
registry where event.type:"change" and
  registry.path: (
    "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllPutSignedDataMsg\\{*}\\Dll",
    "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllPutSignedDataMsg\\{*}\\Dll",
    "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy\\{*}\\$Dll",
    "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy\\{*}\\$Dll"
    ) and
  registry.data.strings:"*.dll"
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "SIP Provider Modification" id: "<i>&lt;redacted&gt;</i>" rule id: "f2c7b914-eda3-40c2-96ac-d23ef91776ca" signals index: ".siem-signals-default"

### SUNBURST Command and Control Activity

```python
network where event.type == "protocol" and network.protocol == "http" and
  process.name : ("ConfigurationWizard.exe",
                  "NetFlowService.exe",
                  "NetflowDatabaseMaintenance.exe",
                  "SolarWinds.Administration.exe",
                  "SolarWinds.BusinessLayerHost.exe",
                  "SolarWinds.BusinessLayerHostx64.exe",
                  "SolarWinds.Collector.Service.exe",
                  "SolarwindsDiagnostics.exe") and
  (http.request.body.content : "*/swip/Upload.ashx*" and http.request.body.content : ("POST*", "PUT*")) or
  (http.request.body.content : ("*/swip/SystemDescription*", "*/swip/Events*") and http.request.body.content : ("GET*", "HEAD*")) and
  not http.request.body.content : "*solarwinds.com*"
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "SUNBURST Command and Control Activity" id: "<i>&lt;redacted&gt;</i>" rule id: "22599847-5d13-48cb-8872-5796fee8692b" signals index: ".siem-signals-default"

### Scheduled Tasks AT Command Enabled

```python
registry where 
 registry.path : "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\Configuration\\EnableAt" and registry.data.strings == "1"
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Scheduled Tasks AT Command Enabled" id: "<i>&lt;redacted&gt;</i>" rule id: "9aa0e1f6-52ce-42e1-abb3-09657cee2698" signals index: ".siem-signals-default"

### SolarWinds Process Disabling Services via Registry

```python
registry where registry.path : "HKLM\\SYSTEM\\*ControlSet*\\Services\\*\\Start" and registry.data.strings == "4" and
 process.name : (
     "SolarWinds.BusinessLayerHost*.exe", 
     "ConfigurationWizard*.exe", 
     "NetflowDatabaseMaintenance*.exe", 
     "NetFlowService*.exe", 
     "SolarWinds.Administration*.exe", 
     "SolarWinds.Collector.Service*.exe" , 
     "SolarwindsDiagnostics*.exe")
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "SolarWinds Process Disabling Services via Registry" id: "<i>&lt;redacted&gt;</i>" rule id: "b9960fef-82c6-4816-befa-44745030e917" signals index: ".siem-signals-default"

### Startup or Run Key Registry Modification

```python
registry where registry.data.strings != null and
 registry.path : (
     /* Machine Hive */
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*", 
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*", 
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\*",
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*", 
     "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\\*",   
     /* Users Hive */
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*", 
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*", 
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\*",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*", 
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\\*"
     ) and
  /* add common legitimate changes without being too restrictive as this is one of the most abused AESPs */
  not registry.data.strings : "ctfmon.exe /n" and
  not (registry.value : "Application Restart #*" and process.name : "csrss.exe") and
  user.id not in ("S-1-5-18", "S-1-5-19", "S-1-5-20") and
  not registry.data.strings : ("?:\\Program Files\\*.exe", "?:\\Program Files (x86)\\*.exe") and
  not process.executable : ("?:\\Windows\\System32\\msiexec.exe", "?:\\Windows\\SysWOW64\\msiexec.exe") and
  not (process.name : "OneDriveSetup.exe" and
       registry.value : ("Delete Cached Standalone Update Binary", "Delete Cached Update Binary", "amd64", "Uninstall *") and
       registry.data.strings : "?:\\Windows\\system32\\cmd.exe /q /c * \"?:\\Users\\*\\AppData\\Local\\Microsoft\\OneDrive\\*\"")
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Startup or Run Key Registry Modification" id: "<i>&lt;redacted&gt;</i>" rule id: "97fc44d3-8dae-4019-ae83-298c3015600f" signals index: ".siem-signals-default"

### Suspicious Browser Child Process

```python
process where event.type in ("start", "process_started") and
  process.parent.name : ("Google Chrome", "Google Chrome Helper*", "firefox", "Opera", "Safari", "com.apple.WebKit.WebContent", "Microsoft Edge") and
  process.name : ("sh", "bash", "dash", "ksh", "tcsh", "zsh", "curl", "wget", "python*", "perl*", "php*", "osascript", "pwsh") and 
  process.command_line != null and 
  not process.args : 
    ( 
      "/Library/Application Support/Microsoft/MAU*/Microsoft AutoUpdate.app/Contents/MacOS/msupdate", 
      "hw.model", 
      "IOPlatformExpertDevice", 
      "/Volumes/Google Chrome/Google Chrome.app/Contents/Frameworks/*/Resources/install.sh",
      "--defaults-torrc", 
      "Chrome.app", 
      "Framework.framework/Versions/*/Resources/keystone_promote_preflight.sh", 
      "/Users/*/Library/Application Support/Google/Chrome/recovery/*/ChromeRecovery", 
      "$DISPLAY", 
      "GIO_LAUNCHED_DESKTOP_FILE_PID=$$"
    )
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Suspicious Browser Child Process" id: "<i>&lt;redacted&gt;</i>" rule id: "080bc66a-5d56-4d1f-8071-817671716db9" signals index: ".siem-signals-default"

### Suspicious DLL Loaded for Persistence or Privilege Escalation

```python
library where dll.name :
  (
  "wlbsctrl.dll",
  "wbemcomn.dll",
  "WptsExtensions.dll",
  "Tsmsisrv.dll",
  "TSVIPSrv.dll",
  "Msfte.dll",
  "wow64log.dll",
  "WindowsCoreDeviceInfo.dll",
  "Ualapi.dll",
  "wlanhlp.dll",
  "phoneinfo.dll",
  "EdgeGdi.dll",
  "cdpsgshims.dll",
  "windowsperformancerecordercontrol.dll",
  "diagtrack_win.dll"
  ) and 
not (dll.code_signature.subject_name : ("Microsoft Windows", "Microsoft Corporation") and dll.code_signature.status : "trusted")
```

```python
[{'dll': {'name': 'wptsextensions.dll', 'code_signature': {'subject_name': 'FyX'}}, 'event': {'category': ['library']}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



SDE says:
> An error occurred during rule execution: message: "verification_exception: [verification_exception] Reason: Found 1 problem
line 19:91: Unknown column [dll.code_signature.status], did you mean any of [dll.code_signature.subject_name, process.code_signature.trusted, process.code_signature.subject_name]?" name: "Suspicious DLL Loaded for Persistence or Privilege Escalation" id: "<i>&lt;redacted&gt;</i>" rule id: "bfeaf89b-a2a7-48a3-817f-e41829dc61ee" signals index: ".siem-signals-default"

### Suspicious Execution - Short Program Name

```python
process where event.type in ("start", "process_started") and length(process.name) > 0 and
 length(process.name) == 5 and host.os.name == "Windows" and length(process.pe.original_file_name) > 5
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Suspicious Execution - Short Program Name" id: "<i>&lt;redacted&gt;</i>" rule id: "17c7f6a5-5bc9-4e1f-92bf-13632d24384d" signals index: ".siem-signals-default"

### Suspicious ImagePath Service Creation

```python
registry where registry.path : "HKLM\\SYSTEM\\ControlSet*\\Services\\*\\ImagePath" and
 /* add suspicious registry ImagePath values here */
 registry.data.strings : ("%COMSPEC%*", "*\\.\\pipe\\*")
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Suspicious ImagePath Service Creation" id: "<i>&lt;redacted&gt;</i>" rule id: "36a8e048-d888-4f61-a8b9-0f9e2e40f317" signals index: ".siem-signals-default"

### Suspicious PowerShell Engine ImageLoad

```python
library where dll.name : ("System.Management.Automation.ni.dll", "System.Management.Automation.dll") and
/* add false positives relevant to your environment here */
not process.executable : ("C:\\Windows\\System32\\RemoteFXvGPUDisablement.exe", "C:\\Windows\\System32\\sdiagnhost.exe") and
not process.executable regex~ """C:\\Program Files( \(x86\))?\\*\.exe""" and
  not process.name :
  (
    "Altaro.SubAgent.exe",
    "AppV_Manage.exe",
    "azureadconnect.exe",
    "CcmExec.exe",
    "configsyncrun.exe",
    "choco.exe",
    "ctxappvservice.exe",
    "DVLS.Console.exe",
    "edgetransport.exe",
    "exsetup.exe",
    "forefrontactivedirectoryconnector.exe",
    "InstallUtil.exe",
    "JenkinsOnDesktop.exe",
    "Microsoft.EnterpriseManagement.ServiceManager.UI.Console.exe",
    "mmc.exe",
    "mscorsvw.exe",
    "msexchangedelivery.exe",
    "msexchangefrontendtransport.exe",
    "msexchangehmworker.exe",
    "msexchangesubmission.exe",
    "msiexec.exe",
    "MsiExec.exe",
    "noderunner.exe",
    "NServiceBus.Host.exe",
    "NServiceBus.Host32.exe",
    "NServiceBus.Hosting.Azure.HostProcess.exe",
    "OuiGui.WPF.exe",
    "powershell.exe",
    "powershell_ise.exe",
    "pwsh.exe",
    "SCCMCliCtrWPF.exe",
    "ScriptEditor.exe",
    "ScriptRunner.exe",
    "sdiagnhost.exe",
    "servermanager.exe",
    "setup100.exe",
    "ServiceHub.VSDetouredHost.exe",
    "SPCAF.Client.exe",
    "SPCAF.SettingsEditor.exe",
    "SQLPS.exe",
    "telemetryservice.exe",
    "UMWorkerProcess.exe",
    "w3wp.exe",
    "wsmprovhost.exe"
  )
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Suspicious PowerShell Engine ImageLoad" id: "<i>&lt;redacted&gt;</i>" rule id: "852c1f19-68e8-43a6-9dce-340771fe1be3" signals index: ".siem-signals-default"

### Suspicious Print Spooler Point and Print DLL

```python
sequence by host.id with maxspan=30s
[registry where
 registry.path : "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\*\\SpoolDirectory" and
 registry.data.strings : "C:\\Windows\\System32\\spool\\drivers\\x64\\4"]
[registry where
 registry.path : "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\*\\CopyFiles\\Payload\\Module" and
 registry.data.strings : "C:\\Windows\\System32\\spool\\drivers\\x64\\4\\*"]
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Suspicious Print Spooler Point and Print DLL" id: "<i>&lt;redacted&gt;</i>" rule id: "bd7eefee-f671-494e-98df-f01daf9e5f17" signals index: ".siem-signals-default"

### Suspicious Process Access via Direct System Call

```python
process where event.code == "10" and
 length(winlog.event_data.CallTrace) > 0 and

 /* Sysmon CallTrace starting with unknown memory module instead of ntdll which host Windows NT Syscalls */
 not winlog.event_data.CallTrace : ("?:\\WINDOWS\\SYSTEM32\\ntdll.dll*", "?:\\WINDOWS\\SysWOW64\\ntdll.dll*")
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Suspicious Process Access via Direct System Call" id: "<i>&lt;redacted&gt;</i>" rule id: "2dd480be-1263-4d9c-8672-172928f6789a" signals index: ".siem-signals-default"

### Suspicious Startup Shell Folder Modification

```python
registry where
 registry.path : (
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Common Startup",
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Common Startup",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Startup",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup"
     ) and
  registry.data.strings != null and
  /* Normal Startup Folder Paths */
  not registry.data.strings : (
           "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
           "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
           "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
           "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
           )
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Suspicious Startup Shell Folder Modification" id: "<i>&lt;redacted&gt;</i>" rule id: "c8b150f0-0164-475b-a75e-74b47800a9ff" signals index: ".siem-signals-default"

### Suspicious WMIC XSL Script Execution

```python
sequence by process.entity_id with maxspan = 2m
[process where event.type in ("start", "process_started") and
   (process.name : "WMIC.exe" or process.pe.original_file_name : "wmic.exe") and
   process.args : ("format*:*", "/format*:*", "*-format*:*") and
   not process.command_line : "* /format:table *"]
[library where event.type == "start" and dll.name : ("jscript.dll", "vbscript.dll")]
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Suspicious WMIC XSL Script Execution" id: "<i>&lt;redacted&gt;</i>" rule id: "7f370d54-c0eb-4270-ac5a-9a6020585dc6" signals index: ".siem-signals-default"

### Uncommon Registry Persistence Change

```python
registry where
  /* uncomment once stable length(registry.data.strings) > 0 and */
 registry.path : (
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Runonce\\*",
      "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Load",
      "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Run",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\IconServiceLib",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
      "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AppSetup",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Taskman",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\VmApplet",
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*",
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Shell",
      "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logoff\\Script",
      "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logon\\Script",
      "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Shutdown\\Script",
      "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Startup\\Script",
      "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*",
      "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Shell",
      "HKEY_USERS\\*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logoff\\Script",
      "HKEY_USERS\\*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logon\\Script",
      "HKEY_USERS\\*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Shutdown\\Script",
      "HKEY_USERS\\*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Startup\\Script",
      "HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\*\\ShellComponent",
      "HKLM\\SOFTWARE\\Microsoft\\Windows CE Services\\AutoStartOnConnect\\MicrosoftActiveSync",
      "HKLM\\SOFTWARE\\Microsoft\\Windows CE Services\\AutoStartOnDisconnect\\MicrosoftActiveSync",
      "HKLM\\SOFTWARE\\Microsoft\\Ctf\\LangBarAddin\\*\\FilePath",
      "HKLM\\SOFTWARE\\Microsoft\\Internet Explorer\\Extensions\\*\\Exec",
      "HKLM\\SOFTWARE\\Microsoft\\Internet Explorer\\Extensions\\*\\Script",
      "HKLM\\SOFTWARE\\Microsoft\\Command Processor\\Autorun",
      "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Ctf\\LangBarAddin\\*\\FilePath",
      "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Internet Explorer\\Extensions\\*\\Exec",
      "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Internet Explorer\\Extensions\\*\\Script",
      "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Command Processor\\Autorun",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*\\VerifierDlls",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GpExtensions\\*\\DllName",
      "HKLM\\SYSTEM\\ControlSet*\\Control\\SafeBoot\\AlternateShell",
      "HKLM\\SYSTEM\\ControlSet*\\Control\\Terminal Server\\Wds\\rdpwd\\StartupPrograms",
      "HKLM\\SYSTEM\\ControlSet*\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\InitialProgram",
      "HKLM\\SYSTEM\\ControlSet*\\Control\\Session Manager\\BootExecute",
      "HKLM\\SYSTEM\\ControlSet*\\Control\\Session Manager\\SetupExecute",
      "HKLM\\SYSTEM\\ControlSet*\\Control\\Session Manager\\Execute",
      "HKLM\\SYSTEM\\ControlSet*\\Control\\Session Manager\\S0InitialCommand",
      "HKLM\\SYSTEM\\ControlSet*\\Control\\ServiceControlManagerExtension",
      "HKLM\\SYSTEM\\ControlSet*\\Control\\BootVerificationProgram\\ImagePath",
      "HKLM\\SYSTEM\\Setup\\CmdLine",
      "HKEY_USERS\\*\\Environment\\UserInitMprLogonScript") and

 not registry.data.strings : ("C:\\Windows\\system32\\userinit.exe", "cmd.exe", "C:\\Program Files (x86)\\*.exe",
                              "C:\\Program Files\\*.exe") and
 not (process.name : "rundll32.exe" and registry.path : "*\\Software\\Microsoft\\Internet Explorer\\Extensions\\*\\Script") and
 not process.executable : ("C:\\Windows\\System32\\msiexec.exe",
                           "C:\\Windows\\SysWOW64\\msiexec.exe",
                           "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MsMpEng.exe",
                           "C:\\Program Files\\*.exe",
                           "C:\\Program Files (x86)\\*.exe")
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Uncommon Registry Persistence Change" id: "<i>&lt;redacted&gt;</i>" rule id: "54902e45-3467-49a4-8abc-529f2c8cfb80" signals index: ".siem-signals-default"

### Unusual Persistence via Services Registry

```python
registry where registry.path : ("HKLM\\SYSTEM\\ControlSet*\\Services\\*\\ServiceDLL", "HKLM\\SYSTEM\\ControlSet*\\Services\\*\\ImagePath") and
  not registry.data.strings : ("?:\\windows\\system32\\Drivers\\*.sys",
                               "\\SystemRoot\\System32\\drivers\\*.sys",
                               "\\??\\?:\\Windows\\system32\\Drivers\\*.SYS",
                               "system32\\DRIVERS\\USBSTOR") and
  not (process.name : "procexp??.exe" and registry.data.strings : "?:\\*\\procexp*.sys") and
  not process.executable : ("?:\\Program Files\\*.exe",
                            "?:\\Program Files (x86)\\*.exe",
                            "?:\\Windows\\System32\\svchost.exe",
                            "?:\\Windows\\winsxs\\*\\TiWorker.exe",
                            "?:\\Windows\\System32\\drvinst.exe",
                            "?:\\Windows\\System32\\services.exe",
                            "?:\\Windows\\System32\\msiexec.exe",
                            "?:\\Windows\\System32\\regsvr32.exe")
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Unusual Persistence via Services Registry" id: "<i>&lt;redacted&gt;</i>" rule id: "403ef0d3-8259-40c9-a5b6-d48354712e49" signals index: ".siem-signals-default"

### Unusual Print Spooler Child Process

```python
process where event.type == "start" and
 process.parent.name : "spoolsv.exe" and user.id : "S-1-5-18" and

 /* exclusions for FP control below */
 not process.name : ("splwow64.exe", "PDFCreator.exe", "acrodist.exe", "spoolsv.exe", "msiexec.exe", "route.exe", "WerFault.exe") and
 not process.command_line : "*\\WINDOWS\\system32\\spool\\DRIVERS*" and
 not (process.name : "net.exe" and process.command_line : ("*stop*", "*start*")) and
 not (process.name : ("cmd.exe", "powershell.exe") and process.command_line : ("*.spl*", "*\\program files*", "*route add*")) and
 not (process.name : "netsh.exe" and process.command_line : ("*add portopening*", "*rule name*")) and
 not (process.name : "regsvr32.exe" and process.command_line : "*PrintConfig.dll*")
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Unusual Print Spooler Child Process" id: "<i>&lt;redacted&gt;</i>" rule id: "ee5300a7-7e31-4a72-a258-250abb8b3aa1" signals index: ".siem-signals-default"

### Virtual Private Network Connection Attempt

```python
process where event.type in ("start", "process_started") and
  (
    (process.name : "networksetup" and process.args : "-connectpppoeservice") or
    (process.name : "scutil" and process.args : "--nc" and process.args : "start") or
    (process.name : "osascript" and process.command_line : "osascript*set VPN to service*")
  )
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'networksetup', 'args': ['-connectpppoeservice']}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



SDE says:
> An error occurred during rule execution: message: "verification_exception: [verification_exception] Reason: Found 1 problem
line 5:37: Unknown column [process.command_line], did you mean any of [process.working_directory, process.entity_id, process.executable, process.name, process.parent.name, process.parent.pid]?" name: "Virtual Private Network Connection Attempt" id: "<i>&lt;redacted&gt;</i>" rule id: "15dacaa0-5b90-466b-acab-63435a59701a" signals index: ".siem-signals-default"

### Whitespace Padding in Process Command Line

```python
process where event.type in ("start", "process_started") and
  process.command_line regex ".*[ ]{20,}.*" or 

  /* this will match on 3 or more separate occurrences of 5+ contiguous whitespace characters */
  process.command_line regex ".*(.*[ ]{5,}[^ ]*){3,}.*"
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Whitespace Padding in Process Command Line" id: "<i>&lt;redacted&gt;</i>" rule id: "e0dacebe-4311-4d50-9387-b17e89c2e7fd" signals index: ".siem-signals-default"

### Windows Defender Disabled via Registry Modification

```python
registry where event.type in ("creation", "change") and
  ((registry.path:"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware" and
     registry.data.strings:"1") or
  (registry.path:"HKLM\\System\\ControlSet*\\Services\\WinDefend\\Start" and
     registry.data.strings in ("3", "4")))
```

```python
[]
```



SDE says:
> An error occurred during rule execution: message: "index_not_found_exception: [verification_exception] Reason: Found 1 problem
line -1:-1: Unknown index [*,-*]" name: "Windows Defender Disabled via Registry Modification" id: "<i>&lt;redacted&gt;</i>" rule id: "2ffa1f1e-b6db-47fa-994b-1512743847eb" signals index: ".siem-signals-default"

## Rules with too few signals

### Authorization Plugin Modification

```python
event.category:file and not event.type:deletion and
  file.path:(/Library/Security/SecurityAgentPlugins/* and
  not /Library/Security/SecurityAgentPlugins/TeamViewerAuthPlugin.bundle/Contents/*)
```

```python
[{'event': {'category': ['file'], 'type': ['ZFy']}, 'file': {'path': '/library/security/securityagentplugins/yyfjsviloooh'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



### Azure External Guest User Invitation

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Invite external user" and azure.auditlogs.properties.target_resources.*.display_name:guest and event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.auditlogs', 'outcome': 'Success'}, 'azure': {'auditlogs': {'operation_name': 'Invite external user', 'properties': {'target_resources': {'`*`': {'display_name': 'guest'}}}}}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



### Azure Full Network Packet Capture Detected

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:
    (
        "MICROSOFT.NETWORK/*/STARTPACKETCAPTURE/ACTION" or
        "MICROSOFT.NETWORK/*/VPNCONNECTIONS/STARTPACKETCAPTURE/ACTION" or
        "MICROSOFT.NETWORK/*/PACKETCAPTURES/WRITE"
    ) and 
event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'microsoft.network/vcfuyyfjsvilooo/vpnconnections/startpacketcapture/action'}}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



### Azure Global Administrator Role Addition to PIM User

```python
event.dataset:azure.auditlogs and azure.auditlogs.properties.category:RoleManagement and
    azure.auditlogs.operation_name:("Add eligible member to role in PIM completed (permanent)" or
                                    "Add member to role in PIM completed (timebound)") and
    azure.auditlogs.properties.target_resources.*.display_name:"Global Administrator" and
    event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.auditlogs', 'outcome': 'Success'}, 'azure': {'auditlogs': {'properties': {'category': 'RoleManagement', 'target_resources': {'`*`': {'display_name': 'Global Administrator'}}}, 'operation_name': 'Add eligible member to role in PIM completed (permanent)'}}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



### GCP IAM Custom Role Creation

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.iam.admin.v*.CreateRole and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.iam.admin.vxiutknioixtfl.createrole', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



### GCP IAM Role Deletion

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.iam.admin.v*.DeleteRole and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.iam.admin.vxiutknioixtfl.deleterole', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



### GCP IAM Service Account Key Deletion

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.iam.admin.v*.DeleteServiceAccountKey and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.iam.admin.vxiutknioixtfl.deleteserviceaccountkey', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



### GCP Logging Bucket Deletion

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.logging.v*.ConfigServiceV*.DeleteBucket and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.logging.vxiutknioixtfl.configservicevhmxbnleoaagaifq.deletebucket', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



### GCP Logging Sink Deletion

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.logging.v*.ConfigServiceV*.DeleteSink and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.logging.vxiutknioixtfl.configservicevhmxbnleoaagaifq.deletesink', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



### GCP Logging Sink Modification

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.logging.v*.ConfigServiceV*.UpdateSink and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.logging.vxiutknioixtfl.configservicevhmxbnleoaagaifq.updatesink', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



### GCP Pub/Sub Subscription Creation

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.pubsub.v*.Subscriber.CreateSubscription and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.pubsub.vxiutknioixtfl.subscriber.createsubscription', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



### GCP Pub/Sub Subscription Deletion

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.pubsub.v*.Subscriber.DeleteSubscription and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.pubsub.vxiutknioixtfl.subscriber.deletesubscription', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



### GCP Pub/Sub Topic Creation

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.pubsub.v*.Publisher.CreateTopic and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.pubsub.vxiutknioixtfl.publisher.createtopic', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



### GCP Pub/Sub Topic Deletion

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.pubsub.v*.Publisher.DeleteTopic and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.pubsub.vxiutknioixtfl.publisher.deletetopic', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



### GCP Service Account Creation

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.iam.admin.v*.CreateServiceAccount and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.iam.admin.vxiutknioixtfl.createserviceaccount', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



### GCP Service Account Deletion

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.iam.admin.v*.DeleteServiceAccount and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.iam.admin.vxiutknioixtfl.deleteserviceaccount', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



### GCP Service Account Disabled

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.iam.admin.v*.DisableServiceAccount and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.iam.admin.vxiutknioixtfl.disableserviceaccount', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



### GCP Service Account Key Creation

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.iam.admin.v*.CreateServiceAccountKey and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.iam.admin.vxiutknioixtfl.createserviceaccountkey', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



### LaunchDaemon Creation or Modification and Immediate Loading

```python
sequence by host.id with maxspan=1m
 [file where event.type != "deletion" and file.path in ("/System/Library/LaunchDaemons/*", " /Library/LaunchDaemons/*")]
 [process where event.type in ("start", "process_started") and process.name == "launchctl" and process.args == "load"]
```

```python
[{'event': {'type': ['ZFy'], 'category': ['file']}, 'file': {'path': '/system/library/launchdaemons/yyfjsviloooh'}, 'host': {'id': 'mxB'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}},
{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'launchctl', 'args': ['load']}, 'host': {'id': 'mxB'}, '@timestamp': 1, 'ecs': {'version': '1.12.1'}}]
```



### Persistence via DirectoryService Plugin Modification

```python
event.category:file and not event.type:deletion and
  file.path:/Library/DirectoryServices/PlugIns/*.dsplug
```

```python
[{'event': {'category': ['file'], 'type': ['ZFy']}, 'file': {'path': '/library/directoryservices/plugins/yyfjsviloooh.dsplug'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



### Persistence via Docker Shortcut Modification

```python
event.category : file and event.action : modification and 
 file.path : /Users/*/Library/Preferences/com.apple.dock.plist and 
 not process.name : (xpcproxy or cfprefsd or plutil or jamf or PlistBuddy or InstallerRemotePluginService)
```

```python
[{'event': {'category': ['file'], 'action': 'modification'}, 'file': {'path': '/users/xiutknioixtfl/library/preferences/com.apple.dock.plist'}, 'process': {'name': 'Ezs'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



### Potential Admin Group Account Addition

```python
event.category:process and event.type:(start or process_started) and
 process.name:(dscl or dseditgroup) and process.args:(("/Groups/admin" or admin) and ("-a" or "-append"))
```

```python
[]
```



### Potential Hidden Local User Account Creation

```python
event.category:process and event.type:(start or process_started) and
 process.name:dscl and process.args:(IsHidden and create and (true or 1 or yes))
```

```python
[]
```



### Potential Persistence via Atom Init Script Modification

```python
event.category:"file" and not event.type:"deletion" and
 file.path:/Users/*/.atom/init.coffee and not process.name:(Atom or xpcproxy) and not user.name:root
```

```python
[{'event': {'category': ['file'], 'type': ['ZFy']}, 'file': {'path': '/users/yyfjsviloooh/.atom/init.coffee'}, 'process': {'name': 'mxB'}, 'user': {'name': 'nLe'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



### Potential Process Injection via PowerShell

```python
event.code:"4104" and 
  powershell.file.script_block_text : (
   (VirtualAlloc or VirtualAllocEx or VirtualProtect or LdrLoadDll or LoadLibrary or LoadLibraryA or
      LoadLibraryEx or GetProcAddress or OpenProcess or OpenProcessToken or AdjustTokenPrivileges) and
   (WriteProcessMemory or CreateRemoteThread or NtCreateThreadEx or CreateThread or QueueUserAPC or
      SuspendThread or ResumeThread)
  )
```

```python
[]
```



### SoftwareUpdate Preferences Modification

```python
event.category:process and event.type:(start or process_started) and
 process.name:defaults and 
 process.args:(write and "-bool" and (com.apple.SoftwareUpdate or /Library/Preferences/com.apple.SoftwareUpdate.plist) and not (TRUE or true))
```

```python
[]
```



### Suspicious Calendar File Modification

```python
event.category:file and event.action:modification and
  file.path:/Users/*/Library/Calendars/*.calendar/Events/*.ics and
  process.executable:
  (* and not 
    (
      /System/Library/* or 
      /System/Applications/Calendar.app/Contents/MacOS/* or 
      /usr/libexec/xpcproxy or 
      /sbin/launchd or 
      /Applications/*
    )
  )
```

```python
[{'event': {'category': ['file'], 'action': 'modification'}, 'file': {'path': '/users/xiutknioixtfl/library/calendars/hmxbnleoaagaifq.calendar/events/eewvpymgznf.ics'}, 'process': {'executable': 'mlO'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
```



### Web Application Suspicious Activity: No User Agent

```python
url.path:*
```

```python
[]
```



### Windows CryptoAPI Spoofing Vulnerability (CVE-2020-0601 - CurveBall)

```python
event.provider:"Microsoft-Windows-Audit-CVE" and message:"[CVE-2020-0601]"
```

```python
[]
```

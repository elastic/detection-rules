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
   1. [Rules with no signals](#rules-with-no-signals)
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
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKINTERFACES/TAPCONFIGURATIONS/WRITE'}}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKINTERFACES/TAPCONFIGURATIONS/WRITE'}}, '@timestamp': 1, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKINTERFACES/TAPCONFIGURATIONS/DELETE'}}, '@timestamp': 2, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKINTERFACES/TAPCONFIGURATIONS/DELETE'}}, '@timestamp': 3, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKINTERFACES/WRITE'}}, '@timestamp': 4, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKINTERFACES/WRITE'}}, '@timestamp': 5, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKINTERFACES/JOIN/ACTION'}}, '@timestamp': 6, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKINTERFACES/JOIN/ACTION'}}, '@timestamp': 7, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKINTERFACES/DELETE'}}, '@timestamp': 8, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKINTERFACES/DELETE'}}, '@timestamp': 9, 'ecs': {'version': '1.12.1'}}]
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

## Rules with no signals

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
[{'event': {'dataset': 'azure.auditlogs', 'outcome': 'Success'}, 'azure': {'auditlogs': {'operation_name': 'Invite external user', 'properties': {'target_resources': {'`*`': {'display_name': 'guest'}}}}}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'azure.auditlogs', 'outcome': 'success'}, 'azure': {'auditlogs': {'operation_name': 'Invite external user', 'properties': {'target_resources': {'`*`': {'display_name': 'guest'}}}}}, '@timestamp': 1, 'ecs': {'version': '1.12.1'}}]
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
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'microsoft.network/vcfuyyfjsvilooo/vpnconnections/startpacketcapture/action'}}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'microsoft.network/mxbnleoaaga/vpnconnections/startpacketcapture/action'}}, '@timestamp': 1, 'ecs': {'version': '1.12.1'}}]
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
[{'event': {'dataset': 'azure.auditlogs', 'outcome': 'Success'}, 'azure': {'auditlogs': {'properties': {'category': 'RoleManagement', 'target_resources': {'`*`': {'display_name': 'Global Administrator'}}}, 'operation_name': 'Add eligible member to role in PIM completed (permanent)'}}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'azure.auditlogs', 'outcome': 'success'}, 'azure': {'auditlogs': {'properties': {'category': 'RoleManagement', 'target_resources': {'`*`': {'display_name': 'Global Administrator'}}}, 'operation_name': 'Add eligible member to role in PIM completed (permanent)'}}, '@timestamp': 1, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'azure.auditlogs', 'outcome': 'Success'}, 'azure': {'auditlogs': {'properties': {'category': 'RoleManagement', 'target_resources': {'`*`': {'display_name': 'Global Administrator'}}}, 'operation_name': 'Add member to role in PIM completed (timebound)'}}, '@timestamp': 2, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'azure.auditlogs', 'outcome': 'success'}, 'azure': {'auditlogs': {'properties': {'category': 'RoleManagement', 'target_resources': {'`*`': {'display_name': 'Global Administrator'}}}, 'operation_name': 'Add member to role in PIM completed (timebound)'}}, '@timestamp': 3, 'ecs': {'version': '1.12.1'}}]
```



### GCP IAM Custom Role Creation

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.iam.admin.v*.CreateRole and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.iam.admin.vxiutknioixtfl.createrole', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.iam.admin.vmxbnleoaaga.createrole', 'outcome': 'success'}, '@timestamp': 1, 'ecs': {'version': '1.12.1'}}]
```



### GCP IAM Role Deletion

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.iam.admin.v*.DeleteRole and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.iam.admin.vxiutknioixtfl.deleterole', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.iam.admin.vmxbnleoaaga.deleterole', 'outcome': 'success'}, '@timestamp': 1, 'ecs': {'version': '1.12.1'}}]
```



### GCP IAM Service Account Key Deletion

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.iam.admin.v*.DeleteServiceAccountKey and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.iam.admin.vxiutknioixtfl.deleteserviceaccountkey', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.iam.admin.vmxbnleoaaga.deleteserviceaccountkey', 'outcome': 'success'}, '@timestamp': 1, 'ecs': {'version': '1.12.1'}}]
```



### GCP Logging Bucket Deletion

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.logging.v*.ConfigServiceV*.DeleteBucket and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.logging.vxiutknioixtfl.configservicevhmxbnleoaagaifq.deletebucket', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.logging.vewvpymgznfmlop.configservicevolw.deletebucket', 'outcome': 'success'}, '@timestamp': 1, 'ecs': {'version': '1.12.1'}}]
```



### GCP Logging Sink Deletion

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.logging.v*.ConfigServiceV*.DeleteSink and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.logging.vxiutknioixtfl.configservicevhmxbnleoaagaifq.deletesink', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.logging.vewvpymgznfmlop.configservicevolw.deletesink', 'outcome': 'success'}, '@timestamp': 1, 'ecs': {'version': '1.12.1'}}]
```



### GCP Logging Sink Modification

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.logging.v*.ConfigServiceV*.UpdateSink and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.logging.vxiutknioixtfl.configservicevhmxbnleoaagaifq.updatesink', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.logging.vewvpymgznfmlop.configservicevolw.updatesink', 'outcome': 'success'}, '@timestamp': 1, 'ecs': {'version': '1.12.1'}}]
```



### GCP Pub/Sub Subscription Creation

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.pubsub.v*.Subscriber.CreateSubscription and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.pubsub.vxiutknioixtfl.subscriber.createsubscription', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.pubsub.vmxbnleoaaga.subscriber.createsubscription', 'outcome': 'success'}, '@timestamp': 1, 'ecs': {'version': '1.12.1'}}]
```



### GCP Pub/Sub Subscription Deletion

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.pubsub.v*.Subscriber.DeleteSubscription and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.pubsub.vxiutknioixtfl.subscriber.deletesubscription', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.pubsub.vmxbnleoaaga.subscriber.deletesubscription', 'outcome': 'success'}, '@timestamp': 1, 'ecs': {'version': '1.12.1'}}]
```



### GCP Pub/Sub Topic Creation

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.pubsub.v*.Publisher.CreateTopic and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.pubsub.vxiutknioixtfl.publisher.createtopic', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.pubsub.vmxbnleoaaga.publisher.createtopic', 'outcome': 'success'}, '@timestamp': 1, 'ecs': {'version': '1.12.1'}}]
```



### GCP Pub/Sub Topic Deletion

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.pubsub.v*.Publisher.DeleteTopic and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.pubsub.vxiutknioixtfl.publisher.deletetopic', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.pubsub.vmxbnleoaaga.publisher.deletetopic', 'outcome': 'success'}, '@timestamp': 1, 'ecs': {'version': '1.12.1'}}]
```



### GCP Service Account Creation

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.iam.admin.v*.CreateServiceAccount and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.iam.admin.vxiutknioixtfl.createserviceaccount', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.iam.admin.vmxbnleoaaga.createserviceaccount', 'outcome': 'success'}, '@timestamp': 1, 'ecs': {'version': '1.12.1'}}]
```



### GCP Service Account Deletion

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.iam.admin.v*.DeleteServiceAccount and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.iam.admin.vxiutknioixtfl.deleteserviceaccount', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.iam.admin.vmxbnleoaaga.deleteserviceaccount', 'outcome': 'success'}, '@timestamp': 1, 'ecs': {'version': '1.12.1'}}]
```



### GCP Service Account Disabled

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.iam.admin.v*.DisableServiceAccount and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.iam.admin.vxiutknioixtfl.disableserviceaccount', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.iam.admin.vmxbnleoaaga.disableserviceaccount', 'outcome': 'success'}, '@timestamp': 1, 'ecs': {'version': '1.12.1'}}]
```



### GCP Service Account Key Creation

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.iam.admin.v*.CreateServiceAccountKey and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.iam.admin.vxiutknioixtfl.createserviceaccountkey', 'outcome': 'success'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.iam.admin.vmxbnleoaaga.createserviceaccountkey', 'outcome': 'success'}, '@timestamp': 1, 'ecs': {'version': '1.12.1'}}]
```



### LaunchDaemon Creation or Modification and Immediate Loading

```python
sequence by host.id with maxspan=1m
 [file where event.type != "deletion" and file.path in ("/System/Library/LaunchDaemons/*", " /Library/LaunchDaemons/*")]
 [process where event.type in ("start", "process_started") and process.name == "launchctl" and process.args == "load"]
```

```python
[{'event': {'type': ['ZFy'], 'category': ['file']}, 'file': {'path': '/system/library/launchdaemons/yyfjsviloooh'}, 'host': {'id': 'mxB'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'launchctl', 'args': ['load']}, 'host': {'id': 'mxB'}, '@timestamp': 1, 'ecs': {'version': '1.12.1'}},
 {'event': {'type': ['nLe'], 'category': ['file']}, 'file': {'path': '/system/library/launchdaemons/'}, 'host': {'id': 'NVR'}, '@timestamp': 2, 'ecs': {'version': '1.12.1'}},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'launchctl', 'args': ['load']}, 'host': {'id': 'NVR'}, '@timestamp': 3, 'ecs': {'version': '1.12.1'}},
 {'event': {'type': ['cym'], 'category': ['file']}, 'file': {'path': ' /library/launchdaemons/wvpymgznfmlopzr'}, 'host': {'id': 'gUv'}, '@timestamp': 4, 'ecs': {'version': '1.12.1'}},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'launchctl', 'args': ['load']}, 'host': {'id': 'gUv'}, '@timestamp': 5, 'ecs': {'version': '1.12.1'}},
 {'event': {'type': ['WCi'], 'category': ['file']}, 'file': {'path': ' /library/launchdaemons/fhat'}, 'host': {'id': 'Dgz'}, '@timestamp': 6, 'ecs': {'version': '1.12.1'}},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'launchctl', 'args': ['load']}, 'host': {'id': 'Dgz'}, '@timestamp': 7, 'ecs': {'version': '1.12.1'}}]
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



### Potential Persistence via Atom Init Script Modification

```python
event.category:"file" and not event.type:"deletion" and
 file.path:/Users/*/.atom/init.coffee and not process.name:(Atom or xpcproxy) and not user.name:root
```

```python
[{'event': {'category': ['file'], 'type': ['ZFy']}, 'file': {'path': '/users/yyfjsviloooh/.atom/init.coffee'}, 'process': {'name': 'mxB'}, 'user': {'name': 'nLe'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}}]
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



## Rules with too few signals

### File and Directory Discovery

```python
sequence by agent.id, user.name with maxspan=1m
[process where event.type in ("start", "process_started") and
  ((process.name : "cmd.exe" or process.pe.original_file_name == "Cmd.Exe") and process.args : "dir") or
    process.name : "tree.com"]
[process where event.type in ("start", "process_started") and
  ((process.name : "cmd.exe" or process.pe.original_file_name == "Cmd.Exe") and process.args : "dir") or
    process.name : "tree.com"]
[process where event.type in ("start", "process_started") and
  ((process.name : "cmd.exe" or process.pe.original_file_name == "Cmd.Exe") and process.args : "dir") or
    process.name : "tree.com"]
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'ZFy'}, 'user': {'name': 'XIU'}, '@timestamp': 0, 'ecs': {'version': '1.12.1'}},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'ZFy'}, 'user': {'name': 'XIU'}, '@timestamp': 1, 'ecs': {'version': '1.12.1'}},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'ZFy'}, 'user': {'name': 'XIU'}, '@timestamp': 2, 'ecs': {'version': '1.12.1'}},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'tkN'}, 'user': {'name': 'Ioi'}, '@timestamp': 3, 'ecs': {'version': '1.12.1'}},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'tkN'}, 'user': {'name': 'Ioi'}, '@timestamp': 4, 'ecs': {'version': '1.12.1'}},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'tkN'}, 'user': {'name': 'Ioi'}, '@timestamp': 5, 'ecs': {'version': '1.12.1'}},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'xTF'}, 'user': {'name': 'lEz'}, '@timestamp': 6, 'ecs': {'version': '1.12.1'}},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'xTF'}, 'user': {'name': 'lEz'}, '@timestamp': 7, 'ecs': {'version': '1.12.1'}},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'xTF'}, 'user': {'name': 'lEz'}, '@timestamp': 8, 'ecs': {'version': '1.12.1'}},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'swu'}, 'user': {'name': 'EEX'}, '@timestamp': 9, 'ecs': {'version': '1.12.1'}}]
```

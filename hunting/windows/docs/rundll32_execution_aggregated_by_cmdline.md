# Rundll32 execution aggregated by cmdline

---

## Metadata

- **Author:** Elastic
- **UUID:** `30f37cd2-c1d8-4554-bb4a-ed76de9e6857`
- **Integration:** `logs-endpoint.events.process-*, logs-windows.sysmon_operational-*, logs-system.security-*`
- **Language:** `ES|QL`

## Query

```sql
from logs-endpoint.events.process-*, logs-windows.sysmon_operational-*, logs-system.security-*
| where  @timestamp > now() - 7 day
| where host.os.family == "windows" and event.category == "process" and event.action in ("start", "Process creation", "created-process") and 
  process.name.caseless == "rundll32.exe" and 
  not process.command_line rlike """.*(zzzzInvokeManagedCustomActionOutOfProc|GeneralTel.dll,RunInUserCxt|ShOpenVerbApplication|davclnt.dll,DavSetCookie|FileProtocolHandler|EDGEHTML.dll|FirewallControlPanel.dll,ShowNotificationDialog|printui.dll,PrintUIEntryDPIAware|Program Files|SHCreateLocalServerRunDll|ImageView_Fullscreen|StatusMonitorEntryPoint|Control_RunDLL|HotPlugSafeRemovalDriveNotification|AppxDeploymentClient.dll|acproxy.dll,PerformAutochkOperations|CapabilityAccessManagerDoStoreMaintenance|dfshim.dll|display.dll,ShowAdapterSettings|ForceProxyDetectionOnNextRun|PfSvWsSwapAssessmentTask|acmigration.dll,ApplyMigrationShims|LenovoBatteryGaugePackage.dll|-localserver|DriverStore|CnmDxPEntryPoint|DeferredDelete|DeviceProperties_RunDLL|AppxDeploymentClient.dll|spool\\DRIVERS|printui.dll,PrintUIEntry|DfdGetDefaultPolicyAndSMART|cryptext.dll,CryptExt|WininetPlugin.dll|ClearMyTracksByProcess|SusRunTask|OpenURL|CleanupTemporaryState).*"""
| keep process.parent.name, process.command_line, host.id
| eval cmdline = replace(process.command_line, """[cC]:\\[uU][sS][eE][rR][sS]\\[a-zA-Z0-9\.\-\_\$~ ]+\\""", "C:\\\\users\\\\user\\\\")
| eval cmdline = replace(cmdline, """([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|ns[a-z][A-Z0-9]{3,4}\.tmp|DX[A-Z0-9]{3,4}\.tmp|7z[A-Z0-9]{3,5}\.tmp|[0-9\.\-\_]{3,})""", "")
| stats hosts =count_distinct(host.id), total = count() by cmdline, process.parent.name
| where hosts == 1
```

## Notes

- Execution of DLLs from suspicious paths or with suspicious export function names or from suspicious parent should be further reviewed.
- Parents such as svchost, explorer.exe, wmiprvse.exe, winword.exe and others should be carefully reviewed.
## MITRE ATT&CK Techniques

- [T1127](https://attack.mitre.org/techniques//T1127)

- [T1218](https://attack.mitre.org/techniques//T1218)

- [T1218.011](https://attack.mitre.org/techniques//T1218/011)

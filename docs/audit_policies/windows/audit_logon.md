# Audit Logon

## Setup

Some detection rules require monitoring logon events to track user authentication attempts, detect unauthorized access, and investigate security incidents. Enabling this setting provides visibility into successful and failed logon attempts, helping strengthen security and compliance.

### Enable Audit Policy via Group Policy

To enable `Audit logon` events across a group of servers using Active Directory Group Policies, administrators must enable the `Audit logon` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
Logon/Logoff >
Audit Logon (Success,Failure)
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"Logon" /success:enable /failure:enable
```

## Event IDs

When this audit policy is enabled, the following event IDs may be generated:

* **4624**: An account was successfully logged on.
* **4625**: An account failed to log on.
* **4648**: A logon was attempted using explicit credentials.
* **4675**: SIDs were filtered.

## Related Rules

Use the following GitHub search to identify rules that use the events listed:

[Elastic Detection Rules Github Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Windows+Security+Event+Logs%22+AND+%28%224624%22+OR+%22logged-in%22+OR+%224625%22+OR+%22logon-failed%22+OR+%224648%22+OR+%22logged-in-explicit%22+OR+%224675%22+OR+%22sids-filtered%22%29++language%3ATOML+AND+NOT+%28%22%28for+example%2C+4624%29%22+OR+%22Review+the+event+ID+4624%22+OR+%22e.g.%2C+4624%22+OR+%22Correlate+security+events+4662+and+4624%22%29&type=code)

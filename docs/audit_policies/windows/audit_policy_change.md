# Audit Policy Change

## Setup

Some detection rules require tracking changes to audit policies to detect unauthorized modifications or misconfigurations. Enabling this setting ensures visibility into audit policy changes, helping to maintain compliance and security.

### Enable Audit Policy via Group Policy

To enable `Audit Audit Policy Change` across a group of servers using Active Directory Group Policies, administrators must enable the `Audit Audit Policy Change` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration >
Windows Settings >
Security Settings >
Advanced Security Audit Policy Settings >
Audit Policies >
Policy Change >
Audit Audit Policy Change (Success,Failure)
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
```

## Event IDs

When this audit policy is enabled, the following event IDs may be generated:

* **4715**: The audit policy (SACL) on an object was changed.
* **4719**: System audit policy was changed.
* **4817**: Auditing settings on object were changed.
* **4902**: The Per-user audit policy table was created.
* **4904**: An attempt was made to register a security event source.
* **4905**: An attempt was made to unregister a security event source.
* **4906**: The CrashOnAuditFail value has changed.
* **4907**: Auditing settings on object were changed.
* **4908**: Special Groups Logon table modified.
* **4912**: Per User Audit Policy was changed.

## Related Rules

Use the following GitHub search to identify rules that use the events listed:

[Elastic Detection Rules Github Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Windows+Security+Event+Logs%22+AND+%28%224715%22+OR+%22object-audit-policy-changed%22+OR+%224719%22+OR+%22changed-audit-config%22+OR+%224817%22+OR+%22object-audit-changed%22+OR+%224902%22+OR+%22user-audit-policy-created%22+OR+%224904%22+OR+%22security-event-source-added%22+OR+%224905%22+OR+%22security-event-source-removed%22+OR+%224906%22+OR+%22crash-on-audit-changed%22+OR+%224907%22+OR+%22audit-setting-changed%22+OR+%224908%22+OR+%22special-group-table-changed%22+OR+%224912%22+OR+%22per-user-audit-policy-changed%22%29++language%3ATOML+AND+NOT+%28%22-4715-%22+OR+%224715d20eb204%22+OR+%22-4907-%22+OR+%22D61349046527%22%29&type=code)

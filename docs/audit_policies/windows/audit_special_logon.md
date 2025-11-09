# Audit Special Logon

## Setup

Some detection rules require monitoring special logon events to track privileged account usage. Special logon events indicate that an account with elevated privileges (such as administrators or service accounts) has logged in, helping detect unauthorized access or privilege escalation attempts.

### Enable Audit Policy via Group Policy

To enable `Audit Special Logon` across a group of servers using Active Directory Group Policies, administrators must enable the `Audit Special Logon` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration > 
Policies > 
Windows Settings > 
Security Settings > 
Advanced Audit Policies Configuration > 
Audit Policies > 
Logon/Logoff > 
Audit Special Logon (Success)
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"Special Logon" /success:enable /failure:enable
```

## Event IDs

When this audit policy is enabled, the following event IDs may be generated:

* **4672**: Special privileges assigned to new logon.
* **4964**: Special groups have been assigned to a new logon.

## Related Rules

Use the following GitHub search to identify rules that use the events listed:

[Elastic Detection Rules Github Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Windows+Security+Event+Logs%22+AND+%28%224672%22+OR+%22logged-in-special%22+OR+%224964%22%29++language%3ATOML&type=code)

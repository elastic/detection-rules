# Audit Detailed File Share

## Setup

Some detection rules require monitoring file share access to detect unauthorized access attempts or modifications. Enabling this setting helps improve security visibility and ensures compliance by tracking access to shared files and folders.

**Caution:** Enabling this audit policy can generate a high volume of events. Evaluate the audit policy in a group of servers to measure volume and filter unwanted events before deploying in the entire domain.

### Enable Audit Policy via Group Policy

To enable `Audit Detailed File Share` across a group of servers using Active Directory Group Policies, administrators must enable the `Audit Detailed File Share` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
Object Access >
Audit Detailed File Share (Success,Failure)
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"File Share" /success:enable /failure:disable
```

## Event IDs

When this audit policy is enabled, the following event IDs may be generated:

* **5145**: A network share object was checked to see whether client can be granted desired access.

## Related Rules

Use the following GitHub search to identify rules that use the events listed:

[Elastic Detection Rules Github Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Windows+Security+Event+Logs%22+AND+%28%225145%22+OR+%22network-share-object-access-checked%22%29++language%3ATOML&type=code)

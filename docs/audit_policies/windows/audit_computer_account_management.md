# Audit Computer Account Management

## Setup

Some detection rules require monitoring computer account management events to track changes to computer accounts in the domain. Enabling this setting provides visibility into when computer accounts are created, changed, or deleted, which is crucial for detecting potential malicious activity like adding unauthorized computer accounts.

### Enable Audit Policy via Group Policy

To enable `Audit Computer Account Management` events across a group of servers using Active Directory Group Policies, administrators must enable the `Audit Computer Account Management` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
Account Management >
Audit Computer Account Management (Success,Failure)
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"Computer Account Management" /success:enable /failure:enable
```

## Event IDs

When this audit policy is enabled, the following event IDs may be generated:

* **4741**: A computer account was created.
* **4742**: A computer account was changed.
* **4743**: A computer account was deleted.

## Related Rules

Use the following GitHub search to identify rules that use the events listed:

[Elastic Detection Rules Github Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Windows+Security+Event+Logs%22+AND+%28%224741%22+OR+%22added-computer-account%22+OR+%224742%22+OR+%22changed-computer-account%22+OR+%224743%22+OR+%22deleted-computer-account%22%29+language%3ATOML+AND+NOT+%28%22%28for+example%2C+4741%29%22+OR+%22Review+the+event+ID+4741%22+OR+%22e.g.%2C+4741%22%29&type=code)

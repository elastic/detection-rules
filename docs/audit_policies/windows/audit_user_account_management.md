# Audit User Account Management

## Setup

Some detection rules require monitoring user account management activities to detect unauthorized account creations, modifications, or deletions. Enabling this setting ensures visibility into critical account changes, helping maintain security and compliance by tracking administrative actions related to user accounts.

### Enable Audit Policy via Group Policy

To enable `Audit User Account Management` across a group of servers using Active Directory Group Policies, administrators must enable the `Audit User Account Management` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
Account Management >
Audit User Account Management (Success,Failure)
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"User Account Management" /success:enable /failure:enable
```

## Event IDs

When this audit policy is enabled, the following event IDs may be generated:

* **4720**: A user account was created.
* **4722**: A user account was enabled.
* **4723**: An attempt was made to change an account's password.
* **4724**: An attempt was made to reset an account's password.
* **4725**: A user account was disabled.
* **4726**: A user account was deleted.
* **4738**: A user account was changed.
* **4740**: A user account was locked out.
* **4765**: SID History was added to an account.
* **4766**: An attempt to add SID History to an account failed.
* **4767**: A user account was unlocked.
* **4780**: The ACL was set on accounts which are members of administrators groups.
* **4781**: The name of an account was changed.
* **4794**: An attempt was made to set the Directory Services Restore Mode administrator password.
* **4798**: A user's local group membership was enumerated.
* **5376**: Credential Manager credentials were backed up.
* **5377**: Credential Manager credentials were restored from a backup.

## Related Rules

Use the following GitHub search to identify rules that use the events listed:

[Elastic Detection Rules Github Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Windows+Security+Event+Logs%22+AND+%28%224720%22+OR+%22added-user-account%22+OR+%224722%22+OR+%22enabled-user-account%22+OR+%224723%22+OR+%22changed-password%22+OR+%224724%22+OR+%22reset-password%22+OR+%224725%22+OR+%22disabled-user-account%22+OR+%224726%22+OR+%22deleted-user-account%22+OR+%224738%22+OR+%22modified-user-account%22+OR+%224740%22+OR+%22locked-out-user-account%22+OR+%224765%22+OR+%224766%22+OR+%224767%22+OR+%22unlocked-user-account%22+OR+%224780%22+OR+%224781%22+OR+%22renamed-user-account%22+OR+%224794%22+OR+%224798%22+OR+%22group-membership-enumerated%22+OR+%225376%22+OR+%225377%22%29++language%3ATOML&type=code)

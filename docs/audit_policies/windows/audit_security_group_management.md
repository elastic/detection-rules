# Audit Security Group Management

## Setup

Some detection rules require monitoring security group management to detect unauthorized changes to user group memberships, which can affect access control and security policies. Enabling this setting ensures visibility into modifications of security groups, helping maintain security and compliance.

### Enable Audit Policy via Group Policy

To enable `Audit Security Group Management` across a group of servers using Active Directory Group Policies, administrators must enable the `Audit Security Group Management` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
Account Management >
Audit Security Group Management (Success,Failure)
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"Security Group Management" /success:enable /failure:enable
```

## Event IDs

When this audit policy is enabled, the following event IDs may be generated:

* **4727**: A security-enabled global group was created.
* **4728**: A member was added to a security-enabled global group.
* **4729**: A member was removed from a security-enabled global group.
* **4730**: A security-enabled global group was deleted.
* **4731**: A security-enabled local group was created.
* **4732**: A member was added to a security-enabled local group.
* **4733**: A member was removed from a security-enabled local group.
* **4734**: A security-enabled local group was deleted.
* **4735**: A security-enabled local group was changed.
* **4737**: A security-enabled global group was changed.
* **4754**: A security-enabled universal group was created.
* **4755**: A security-enabled universal group was changed.
* **4756**: A member was added to a security-enabled universal group.
* **4757**: A member was removed from a security-enabled universal group.
* **4758**: A security-enabled universal group was deleted.
* **4764**: A group’s type was changed.
* **4799**: A security-enabled local group membership was enumerated.

## Related Rules

Use the following GitHub search to identify rules that use the events listed:

[Elastic Detection Rules Github Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Windows+Security+Event+Logs%22+AND+%28%224727%22+OR+%22added-group-account%22+OR+%224728%22+OR+%22added-member-to-group%22+OR+%224729%22+OR+%22removed-member-from-group%22+OR+%224730%22+OR+%22deleted-group-account%22+OR+%224731%22+OR+%22added-group-account%22+OR+%224732%22+OR+%22added-member-to-group%22+OR+%224733%22+OR+%22removed-member-from-group%22+OR+%224734%22+OR+%22deleted-group-account%22+OR+%224735%22+OR+%22modified-group-account%22+OR+%224737%22+OR+%22modified-group-account%22+OR+%224754%22+OR+%22added-group-account%22+OR+%224755%22+OR+%22modified-group-account%22+OR+%224756%22+OR+%22added-member-to-group%22+OR+%224757%22+OR+%22removed-member-from-group%22+OR+%224758%22+OR+%22deleted-group-account%22+OR+%224764%22+OR+%22type-changed-group-account%22+OR+%224799%22+OR+%22user-member-enumerated%22%29++language%3ATOML&type=code)

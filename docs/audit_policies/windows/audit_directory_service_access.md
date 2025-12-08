# Audit Directory Service Access

## Setup

Some detection rules require configuring audit policies to generate events when Active Directory objects are accessed. These audit policies apply exclusively to Domain Controllers, as other servers do not produce events related to Active Directory object modifications.

**Caution:** Enabling this audit policy can generate a high volume of events. Evaluate the audit policy in a group of servers to measure volume and filter unwanted events before deploying in the entire domain.

### Enable Audit Policy via Group Policy

To enable `Audit Directory Service Access` on all Domain Controllers via Group Policy, administrators must enable the `Audit Directory Service Access` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
DS Access >
Audit Directory Service Access (Success,Failure)
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"Directory Service Access" /success:enable /failure:enable
```

## Event IDs

When this audit policy is enabled, the following event IDs may be generated:

* **4661**: A handle to an object was requested.
* **4662**: An operation was performed on an object.

## Related Rules

Use the following GitHub search to identify rules that use the events listed:

[Elastic Detection Rules Github Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Windows+Security+Event+Logs%22+AND+%28%224661%22+OR+%224662%22+OR+%22object-operation-performed%22%29++language%3ATOML&type=code)

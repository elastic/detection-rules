# Audit Handle Manipulation

## Setup

Some detection rules require monitoring handle manipulation to detect unauthorized access attempts or suspicious interactions with system objects. Enabling this setting helps improve security visibility by tracking when handles to objects (such as files, registry keys, or processes) are opened or modified.

**Caution:** Enabling this audit policy can generate a high volume of events. Evaluate the audit policy in a group of servers to measure volume and filter unwanted events before deploying in the entire domain.

### Enable Audit Policy via Group Policy

To enable `Audit Handle Manipulation` across a group of servers using Active Directory Group Policies, administrators must enable the `Audit Handle Manipulation` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration >
Windows Settings >
Security Settings >
Advanced Audit Policy Configuration >
Audit Policies >
Object Access >
Audit Handle Manipulation (Success,Failure)
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
```

## Event IDs

When this audit policy is enabled, the following event IDs may be generated:

* **4658**: The handle to an object was closed.
* **4690**: An attempt was made to duplicate a handle to an object.

## Related Rules

Use the following GitHub search to identify rules that use the events listed:

[Elastic Detection Rules Github Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Windows+Security+Event+Logs%22+AND+%28%224658%22+OR+%22handle-closed-object%22+OR+%224690%22+OR+%22duplicate-handle-attempt%22%29++language%3ATOML&type=code)

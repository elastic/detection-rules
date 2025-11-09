# Audit Authorization Policy Change

## Setup

Some detection rules require monitoring changes to authorization policies to detect unauthorized modifications or misconfigurations. Enabling this setting ensures visibility into changes affecting user rights and security policies, helping maintain compliance and security.

**Caution:** Enabling this audit policy can generate a high volume of events. Evaluate the audit policy in a group of servers to measure volume and filter unwanted events before deploying in the entire domain.

### Enable Audit Policy via Group Policy

To enable `Audit Authorization Policy Change` across a group of servers using Active Directory Group Policies, administrators must enable the `Audit Authorization Policy Change` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration >
Windows Settings >
Security Settings >
Advanced Audit Policy Configuration >
Audit Policies >
Policy Change >
Audit Authorization Policy Change (Success,Failure)
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable
```

## Event IDs

When this audit policy is enabled, the following event IDs may be generated:

* **4703**: A user right was adjusted.
* **4704**: A user right was assigned.
* **4705**: A user right was removed.
* **4670**: Permissions on an object were changed.
* **4911**: Resource attributes of the object were changed.
* **4913**: Central Access Policy on the object was changed.

## Related Rules

Use the following GitHub search to identify rules that use the events listed:

[Elastic Detection Rules Github Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Windows+Security+Event+Logs%22+AND+%28%224703%22+OR+%22Token+Right+Adjusted+Events%22+OR+%224704%22+OR+%22user-right-assigned%22+OR+%224705%22+OR+%22user-right-removed%22+OR+%224670%22+OR+%22permissions-changed%22+OR+%224911%22+OR+%224913%22%29++language%3ATOML&type=code)

# Audit Token Right Adjusted Events

## Setup

Some detection rules require monitoring token right adjustments to detect privilege changes in user sessions. Token right adjustments occur when a user's security token is modified to grant or revoke privileges, which can indicate privilege escalation attempts or administrative activity. Enabling this setting enhances visibility into security-sensitive changes affecting user privileges.

**Caution:** Enabling this audit policy can generate a high volume of events. Evaluate the audit policy in a group of servers to measure volume and filter unwanted events before deploying in the entire domain.

### Enable Audit Policy via Group Policy

To enable `Token Right Adjusted Events` across a group of servers using Active Directory Group Policies, administrators must enable the `Token Right Adjusted Events` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
Detailed Tracking >
Token Right Adjusted Events (Success)
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"Token Right Adjusted Events" /success:enable /failure:enable
```

## Event IDs

When this audit policy is enabled, the following event ID may be generated:

* **4703**: A user right was adjusted.

## Related Rules

Use the following GitHub search to identify rules that use the events listed:

[Elastic Detection Rules Github Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Windows+Security+Event+Logs%22+AND+%28%224703%22+OR+%22Token+Right+Adjusted+Events%22%29++language%3ATOML&type=code)

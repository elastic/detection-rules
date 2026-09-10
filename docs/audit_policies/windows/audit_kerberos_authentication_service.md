# Audit Kerberos Authentication Service

## Setup

Some detection rules require monitoring Kerberos ticket-granting ticket (TGT) requests to identify unusual or potentially malicious authentication activity. This audit policy applies exclusively to Domain Controllers, as other systems do not produce these events.

### Enable Audit Policy via Group Policy

To enable `Audit Kerberos Authentication Service` on all Domain Controllers via Group Policy, administrators must enable the `Audit Kerberos Authentication Service` policy. Follow these steps to configure the audit policy via Advanced Audit Policies Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
Account Logon >
Audit Kerberos Authentication Service (Success,Failure)
```

### Enable Locally using auditpol

To enable this policy on a local Domain Controller, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
```

## Event IDs

When this audit policy is enabled, the following event IDs may be generated:

* **4768**: A Kerberos authentication ticket (TGT) was requested.
* **4771**: Kerberos pre-authentication failed.
* **4772**: A Kerberos authentication ticket request failed.

## Related Rules

Use the following GitHub search to identify rules that use the events listed:

[Elastic Detection Rules GitHub Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Windows+Security+Event+Logs%22+AND+%28%224768%22+OR+%224771%22+OR+%224772%22%29+language%3ATOML&type=code)

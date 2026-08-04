# Audit Kerberos Service Ticket Operations

## Setup

Some detection rules require monitoring Kerberos service ticket requests to identify unusual or potentially malicious access to services. This audit policy applies exclusively to Domain Controllers, as other servers do not produce these events.

### Enable Audit Policy via Group Policy

To enable `Audit Kerberos Service Ticket Operations` on all Domain Controllers via Group Policy, administrators must enable the `Audit Kerberos Service Ticket Operations` policy. Follow these steps to configure the audit policy via Advanced Audit Policies Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
Account Logon >
Audit Kerberos Service Ticket Operations (Success,Failure)
```

### Enable Locally using auditpol

To enable this policy on a local Domain Controller, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
```

## Event IDs

When this audit policy is enabled, the following event IDs may be generated:

* **4769**: A Kerberos service ticket was requested.
* **4770**: A Kerberos service ticket was renewed.
* **4773**: A Kerberos service ticket request failed.

## Related Rules

Use the following GitHub search to identify rules that use the events listed:

[Elastic Detection Rules Github Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Windows+Security+Event+Logs%22+AND+%28%224769%22+OR+%224770%22+OR+%224773%22%29+language%3ATOML&type=code)

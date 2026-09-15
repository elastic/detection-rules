# Audit Certification Services

## Setup

Some detection rules require monitoring Active Directory Certificate Services (AD CS) operations to identify suspicious certificate requests and issuance. This audit policy applies to servers that host the Certification Authority role. Both the Windows audit policy and the certification authority (CA) audit filter must be configured to generate Certificate Services events in the Windows Security log.

**Caution:** Certificate request auditing can increase Security log volume on busy certification authorities. Validate log retention and forwarding capacity before broad deployment.

### Enable Audit Policy via Group Policy

To enable `Audit Certification Services` on enterprise certification authorities via Group Policy, administrators must enable the `Audit Certification Services` policy. Follow these steps to configure the policy via Advanced Audit Policy Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policy Configuration >
Audit Policies >
Object Access >
Audit Certification Services (Success,Failure)
```

### Enable Locally using auditpol

To enable this policy on a local certification authority, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"Certification Services" /success:enable /failure:enable
```

### Enable Certification Authority Auditing

The Windows audit policy does not generate certificate request events unless the CA audit filter is also configured. On each certification authority, open the Certification Authority snap-in (`certsrv.msc`), right-click the CA name, select **Properties**, select the **Auditing** tab, and enable **Issue and manage certificate requests**.

Alternatively, run the following commands from an elevated PowerShell session. The `+4` value enables this audit category without clearing other categories from the existing CA audit filter:

```
certutil.exe -setreg CA\AuditFilter +4
Restart-Service certsvc
```

Restarting Certificate Services briefly interrupts certificate enrollment. Apply the change during an approved maintenance window.

### Collect Windows Security Events

Collect the Windows Security log from each certification authority. Detection rules that inspect certificate request attributes require the complete multiline `winlog.event_data.Attributes` value. Dropped, truncated, or rewritten attributes create a visibility gap.

## Event IDs

When this audit policy and the **Issue and manage certificate requests** CA audit filter are enabled, the following request-lifecycle event IDs may be generated:

* **4886**: Certificate Services received a certificate request.
* **4887**: Certificate Services approved a certificate request and issued a certificate.
* **4888**: Certificate Services denied a certificate request.
* **4889**: Certificate Services set the status of a certificate request to pending.

## Related Rules

Use the following GitHub search to identify rules that use the events listed:

[Elastic Detection Rules GitHub Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Windows+Security+Event+Logs%22+AND+%28%224886%22+OR+%224887%22+OR+%224888%22+OR+%224889%22%29+language%3ATOML&type=code)

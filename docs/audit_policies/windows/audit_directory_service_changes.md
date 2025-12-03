# Audit Directory Service Changes

## Setup

Some detection rules require configuring audit policies to generate events when Active Directory objects are modified. These audit policies apply exclusively to Domain Controllers, as other servers do not produce events related to Active Directory object modifications.

**Caution:** Enabling this audit policy can generate a high volume of events. Evaluate the audit policy in a group of servers to measure volume and filter unwanted events before deploying in the entire domain.

### Enable Audit Policy via Group Policy

To enable `Audit Directory Service Changes` on all Domain Controllers via Group Policy, administrators must enable the `Audit Directory Service Changes` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
DS Access >
Audit Directory Service Changes (Success,Failure)
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
```

### Additional Settings

The `Audit Directory Service Changes` policy does not cover all objects monitored by the detection rules. To address these gaps, in addition to enabling the audit policy, configure additional Access Control Entries (ACEs) using [Set-AuditRule](https://github.com/OTRF/Set-AuditRule) to ensure proper monitoring.

Below is a list of example Audit Rules. Modify them to match the Distinguished Names specific to your environment:

Audit changes on the MicrosoftDNS object:

```
Set-AuditRule -AdObjectPath 'AD:\\CN=MicrosoftDNS,DC=DomainDNSZones,DC=Domain,DC=com' -WellKnownSidType WorldSid -Rights CreateChild -InheritanceFlags Descendents -AttributeGUID e0fa1e8c-9b45-11d0-afdd-00c04fd930c9 -AuditFlags Success
```

Audit changes on the msDS-KeyCredentialLink attribute of User objects:

```
Set-AuditRule -AdObjectPath 'AD:\\CN=Users,DC=Domain,DC=com' -WellKnownSidType WorldSid -Rights WriteProperty -InheritanceFlags Children -AttributeGUID 5b47d60f-6090-40b2-9f37-2a4de88f3063 -AuditFlags Success
```

Audit changes on the servicePrincipalName attribute of User objects:

```
Set-AuditRule -AdObjectPath 'AD:\\CN=Users,DC=Domain,DC=com' -WellKnownSidType WorldSid -Rights WriteProperty -InheritanceFlags Children -AttributeGUID f3a64788-5306-11d1-a9c5-0000f80367c1 -AuditFlags Success
```

## Event IDs

When this audit policy is enabled, the following event IDs may be generated:

* **5136**: A directory service object was modified.
* **5137**: A directory service object was created.
* **5138**: A directory service object was undeleted.
* **5139**: A directory service object was moved.
* **5141**: A directory service object was deleted.

## Related Rules

Use the following GitHub search to identify rules that use the events listed:

[Elastic Detection Rules Github Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Windows+Security+Event+Logs%22+AND+%28%225136%22+OR+%22directory-service-object-modified%22+OR+%225137%22+OR+%225138%22+OR+%225139%22+OR+%225141%22%29++language%3ATOML&type=code)

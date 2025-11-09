# Audit Security System Extension

## Setup

Some detection rules require monitoring security system extensions to detect unauthorized modifications, such as the installation of new system services, drivers, or security-related components. Enabling this setting helps ensure visibility into critical system changes that could impact security and system integrity.

### Enable Audit Policy via Group Policy

To enable `Audit Security System Extension` across a group of servers using Active Directory Group Policies, administrators must enable the `Audit Security System Extension` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
System >
Audit Security System Extension (Success)
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"Security System Extension" /success:enable /failure:enable
```

## Event IDs

When this audit policy is enabled, the following event IDs may be generated:

* **4610**: An authentication package has been loaded by the Local Security Authority.
* **4611**: A trusted logon process has been registered with the Local Security Authority.
* **4614**: A notification package has been loaded by the Security Account Manager.
* **4622**: A security package has been loaded by the Local Security Authority.
* **4697**: A service was installed in the system.

## Related Rules

Use the following GitHub search to identify rules that use the events listed:

[Elastic Detection Rules Github Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Windows+Security+Event+Logs%22+AND+%28%224610%22+OR+%22authentication-package-loaded%22+OR+%224611%22+OR+%22trusted-logon-process-registered%22+OR+%224614%22+OR+%22notification-package-loaded%22+OR+%224622%22+OR+%22security-package-loaded%22+OR+%224697%22+OR+%22service-installed%22%29++language%3ATOML&type=code)

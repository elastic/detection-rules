# Audit Other Object Access Events

## Setup

Some detection rules require monitoring other object access events to detect unauthorized actions or system modifications. Enabling this setting allows you to monitor operations with scheduled tasks, COM+ objects and indirect object access requests.

### Enable Audit Policy via Group Policy

To enable `Audit Other Object Access Events` across a group of servers using Active Directory Group Policies, administrators must enable the `Audit Other Object Access Events` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration >
Windows Settings >
Security Settings >
Advanced Audit Policy Configuration >
Audit Policies >
Object Access >
Audit Other Object Access Events (Success,Failure)
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

## Event IDs

When this audit policy is enabled, the following event IDs may be generated:

* **4671**: An application attempted to access a blocked ordinal through the TBS.
* **4691**: Indirect access to an object was requested.
* **4698**: A scheduled task was created.
* **4699**: A scheduled task was deleted.
* **4700**: A scheduled task was enabled.
* **4701**: A scheduled task was disabled.
* **4702**: A scheduled task was updated.
* **5148**: The Windows Filtering Platform has detected a DoS attack and entered a defensive mode; packets associated with this attack will be discarded.
* **5149**: The DoS attack has subsided and normal processing is being resumed.
* **5888**: An object in the COM+ Catalog was modified.
* **5889**: An object was deleted from the COM+ Catalog.
* **5890**: An object was added to the COM+ Catalog.

## Related Rules

Use the following GitHub search to identify rules that use the events listed:

[Elastic Detection Rules Github Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Windows+Security+Event+Logs%22+AND+%28%224671%22+OR+%224691%22+OR+%22indirect-object-access-requested%22+OR+%224698%22+OR+%22scheduled-task-created%22+OR+%224699%22+OR+%22scheduled-task-deleted%22+OR+%224700%22+OR+%22scheduled-task-enabled%22+OR+%224701%22+OR+%22scheduled-task-disabled%22+OR+%224702%22+OR+%22scheduled-task-updated%22+OR+%225148%22+OR+%225149%22+OR+%225888%22+OR+%225889%22+OR+%225890%22%29++language%3ATOML+AND+NOT+%28%22-4691-%22+OR+%2214691%22+OR+%22035889c4%22%29&type=code)

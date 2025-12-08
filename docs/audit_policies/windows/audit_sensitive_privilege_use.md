# Audit Sensitive Privilege Use

## Setup

Some detection rules require monitoring the use of sensitive privileges to detect privilege escalation attempts or unauthorized actions. Enabling this setting provides visibility into when sensitive privileges are used, helping to strengthen security and compliance.

**Caution:** Enabling this audit policy can generate a high volume of events. Evaluate the audit policy in a group of servers to measure volume and filter unwanted events before deploying in the entire domain.

### Enable Audit Policy via Group Policy

To enable `Audit Sensitive Privilege Use` across a group of servers using Active Directory Group Policies, administrators must enable the `Audit Sensitive Privilege Use` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration > 
Policies > 
Windows Settings > 
Security Settings > 
Advanced Audit Policies Configuration > 
Audit Policies > 
Privilege Use > 
Audit Sensitive Privilege Use (Success)
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
```

## Event IDs

When this audit policy is enabled, the following event IDs may be generated:

* **4673**: A privileged service was called.
* **4674**: An operation was attempted on a privileged object.
* **4985**: The state of a transaction has changed.

## Related Rules

Use the following GitHub search to identify rules that use the events listed:

[Elastic Detection Rules Github Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Windows+Security+Event+Logs%22+AND+%28%224673%22+OR+%22privileged-service-called%22+OR+%224674%22+OR+%22privileged-operation%22+OR+%224985%22+OR+%22state-of-transaction-has-changed%22%29++language%3ATOML+AND+NOT+%22%25%2514674%22&type=code)

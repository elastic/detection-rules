# Audit Filtering Platform Packet Drop

## Setup

Some detection rules require monitoring Filtering Platform Packet Drop events to detect when network packets are being dropped by the Windows Filtering Platform (WFP). Enabling this setting provides visibility into network traffic that is being blocked, which can be an indicator of malicious activity or network reconnaissance.

**Caution:** Enabling this audit policy can generate a high volume of events. Evaluate the audit policy in a group of servers to measure volume and filter unwanted events before deploying in the entire domain.

### Enable Audit Policy via Group Policy

To enable `Audit Filtering Platform Packet Drop` events across a group of servers using Active Directory Group Policies, administrators must enable the `Audit Filtering Platform Packet Drop` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration > 
Policies > 
Windows Settings > 
Security Settings > 
Advanced Audit Policies Configuration > 
Audit Policies > 
Object Access >
Audit Filtering Platform Packet Drop (Success,Failure)
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
```

## Event IDs

When this audit policy is enabled, the following event IDs may be generated:

* **5152**: The Windows Filtering Platform blocked a packet.
* **5153**: A more restrictive Windows Filtering Platform filter has blocked a packet.

## Related Rules

Use the following GitHub search to identify rules that use the events listed:

[Elastic Detection Rules Github Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Windows+Security+Event+Logs%22+AND+%28%225152%22+OR+%22windows-firewall-packet-drop%22+OR+%225153%22%29+language%3ATOML+AND+NOT+%28%22%28for+example%2C+5152%29%22+OR+%22Review+the+event+ID+5152%22+OR+%22e.g.%2C+5152%22%29&type=code)

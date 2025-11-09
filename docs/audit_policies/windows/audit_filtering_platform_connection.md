# Audit Filtering Platform Connection

## Setup

Some detection rules require monitoring network connections managed by the Windows Filtering Platform (WFP) to detect unauthorized or suspicious network activity.

**Caution:** Enabling this audit policy can generate a high volume of events. Evaluate the audit policy in a group of servers to measure volume and filter unwanted events before deploying in the entire domain.

### Enable Audit Policy via Group Policy

To enable `Audit Filtering Platform Connection` across a group of servers using Active Directory Group Policies, administrators must enable the `Audit Filtering Platform Connection` policy. Follow these steps to configure the audit policy via Advanced Audit Policy Configuration:

```
Computer Configuration >
Windows Settings >
Security Settings >
Advanced Security Audit Policy Settings >
Audit Policies >
Object Access >
Audit Filtering Platform Connection (Success,Failure)
```

### Enable Locally using auditpol

To enable this policy on a local machine, run the following command in an elevated command prompt:

```
auditpol.exe /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

## Event IDs

When this audit policy is enabled, the following event IDs may be generated:

* **5031**: The Windows Firewall Service blocked an application from accepting incoming connections on the network.
* **5150**: The Windows Filtering Platform blocked a packet.
* **5151**: A more restrictive Windows Filtering Platform filter has blocked a packet.
* **5154**: The Windows Filtering Platform has permitted an application or service to listen on a port for incoming connections.
* **5155**: The Windows Filtering Platform has blocked an application or service from listening on a port for incoming connections.
* **5156**: The Windows Filtering Platform has permitted a connection.
* **5157**: The Windows Filtering Platform has blocked a connection.
* **5158**: The Windows Filtering Platform has permitted a bind to a local port.
* **5159**: The Windows Filtering Platform has blocked a bind to a local port.

## Related Rules

Use the following GitHub search to identify rules that use the events listed:

[Elastic Detection Rules Github Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Windows+Security+Event+Logs%22+AND+%28%225031%22+OR+%225150%22+OR+%225151%22+OR+%225154%22+OR+%225155%22+OR+%225156%22+OR+%22windows-firewall-connection%22+OR+%225157%22+OR+%22windows-firewall-packet-block%22+OR+%225158%22+OR+%22windows-firewall-bind-local-port%22+OR+%225159%22%29+language%3ATOML+AND+NOT+%28%224605157a5b80%22+OR+%225151a804f31b%22%29&type=code)

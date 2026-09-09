# macOS Security Events: SSH Authentication

## Setup

Some detection rules require sshd authentication messages from the macOS unified log to detect SSH brute force activity and successful logins that follow it. These messages are collected by the Authentication data stream of the macOS Security Events integration (`logs-macos.authentication-*`). Complete the base integration setup first: [macOS Security Events Integration](macos_security_events.md).

The default Authentication configuration does not collect sshd authentication messages. Edit the integration policy, expand the Authentication data stream's **Advanced options**, and apply the following changes.

### Predicate

Edit the predicate entry `process == "sshd"` to:

```
process == "sshd" OR process == "sshd-session"
```

On OpenSSH 9.8+, the per-connection process execs `sshd-keygen-wrapper` → `sshd` → `sshd-session`, and authentication messages are logged under `sshd-session`, which the default predicate excludes.

### Include info

Enable **Include info**. sshd authentication failure and success messages are logged at Info level and are not collected by default.

### Processors

Ensure the `add_host_metadata` processor from the base setup is present on the Authentication data stream. The rules group and correlate by `host.id`, which is not populated without it.

### Verify

After a test SSH login attempt against the host, search `logs-macos.authentication-*` for documents where `macos.process.image_path` is `/usr/libexec/sshd-session` and `host.id` is populated.

## Related Rules

Use the following GitHub search to identify rules that use these messages:

[Elastic Detection Rules Github Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22macOS+Security+Events%22+AND+%28%22Failed+password+for%22+OR+%22Accepted+*%22%29+language%3ATOML&type=code)
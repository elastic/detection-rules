# TCC (Transparency, Consent, and Control) Events

## Setup

Some detection rules require Apple Event debug telemetry from the `com.apple.TCC` Unified Logs subsystem. Complete the [macOS Unified Logs](readme.md) setup first, then TCC subsystem require no additional OS-level log configuration

> **Note:** This verification step is specific to rules that depend on `com.apple.TCC`.

The integration's debug flag controls what `log stream` displays but does **not** enable debug emission for subsystems suppressed at the OS level. The `com.apple.appleevents` subsystem is suppressed by default and must be explicitly enabled on each monitored host:

Verify:
```
sudo log config --status --subsystem com.apple.tcc
```

Expected output:

```
Mode for 'com.apple.tcc' INFO PERSIST_DEFAULT
```

When the Unified Logs integration is collecting, the following fields are populated for `com.apple.TCC` events
under the default logging preset:

* **unified_log.subsystem**: `com.apple.TCC`
* **unified_log.category**: `access` (access decisions), among others
* **message**: raw Unified Log message, including patterns such as `Handling access request to <service>`,
  `... Denied (Service Policy)`, `does not allow prompting; recording denied`, and
  `Publishing <TCCDEvent...> ... publishAccessChangedEvent`
* **process.name / process.executable**: the requesting process, when resolvable from the log line

Common TCC service identifiers seen in `message`: `kTCCServiceSystemPolicyAllFiles` (Full Disk Access),
`kTCCServiceScreenCapture` (Screen Recording), `kTCCServiceCamera`, `kTCCServiceMicrophone`,
`kTCCServiceListenEvent` (Input Monitoring).

Rules that use structured `unified_log.*` fields require Unified Logs integration package version ≥ 0.5.0.

## Related Rules

* [Full Disk Access Denied via TCC](https://github.com/elastic/detection-rules/blob/main/rules/integrations/unifiedlogs/collection_full_disk_access_denied_via_tcc.toml)

Use the following GitHub search to identify additional rules that use these events:

[Elastic Detection Rules GitHub Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Data+Source%3A+Unified+Logs%22+AND+%22com.apple.TCC%22+language%3ATOML&type=code)

# Apple Events

## Setup

Some detection rules require Apple Event debug telemetry from the `com.apple.appleevents` Unified Logs subsystem. Complete the [macOS Unified Logs](readme.md) setup first, then enable OS-level debug emission on each monitored macOS host.

> **Note:** This step is specific to rules that depend on `com.apple.appleevents`. It is not required for general Unified Logs collection.

The integration's debug flag controls what `log stream` displays but does **not** enable debug emission for subsystems suppressed at the OS level. The `com.apple.appleevents` subsystem is suppressed by default and must be explicitly enabled on each monitored host:

```
sudo log config --subsystem com.apple.appleevents --mode level:debug
```

Verify:

```
sudo log config --status --subsystem com.apple.appleevents
```

Expected output:

```
Mode for 'com.apple.appleevents'  DEBUG PERSIST_DEFAULT
```

Without this, `apple_event.type_code` will not populate and Apple Event detection rules will not fire.

In a fleet deployment, run this command on each macOS endpoint or deploy via MDM/configuration management (for example, Jamf or Munki). The `sudo log config` change persists across reboots on the local host.

## Fields

When the integration is collecting debug-level logs and OS-level debug emission is enabled, the following structured fields may be populated for `com.apple.appleevents` events:

* **unified_log.subsystem**: `com.apple.appleevents`
* **apple_event.type_code**: four-character Apple Event class and ID (for example, `Jons,gClp`, `syso,dlog`, `aevt,odoc`)
* **apple_event.parameters**: Apple Event parameter codes (for example, `htxt`)
* **apple_event.direction**: send or receive direction
* **apple_event.target_process**: target process for the Apple Event
* **message**: raw Unified Log message, including patterns such as `AECreateAppleEvent`

Rules that use structured `apple_event.*` fields require Unified Logs integration package version ≥ 0.5.0.

## Related Rules

* [Suspicious MacOS Apple Events Activity via Scripting Binary](https://github.com/elastic/detection-rules/blob/main/rules/integrations/unifiedlogs/collection_suspicious_apple_events_activity_via_scripting_binary.toml)

Use the following GitHub search to identify additional rules that use these events:

[Elastic Detection Rules GitHub Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Data+Source%3A+Unified+Logs%22+AND+%22com.apple.appleevents%22+language%3ATOML&type=code)

# macOS Unified Logs

macOS Unified Logs configuration required to generate the events that power our detection rules. It serves as a centralized view of the Fleet integration and host-level logging settings we use so you don't need to go through every rule to know the different prerequisites.

Some detection rules require collecting macOS Unified Logs through the Elastic Unified Logs integration. Complete the steps below on each monitored macOS host before enabling those rules.

## Setup

### Install the Unified Logs Integration

The Unified Logs integration (Technical Preview) must be installed and healthy on the macOS host via Fleet.

- In Kibana, go to **Management → Integrations**
- Toggle on **Display beta integrations**
- Search for **Unified Logs** and add it to your agent policy
- Assign the policy to the macOS host running Elastic Agent ≥ 8.19.0

For package details, see the [Custom macOS Unified Logs](https://www.elastic.co/docs/reference/integrations/unifiedlogs) integration documentation.

### Enable debug log collection in the integration

In the Fleet integration config, enable the following toggles:

- **Include info** → on (required; default is off)
- **Include debug** → on (required for Apple Event telemetry and other debug-level subsystems)
- **Must backfill** → on (recommended for initial validation only — disable after confirming data flows)

**Caution:** Debug-level Unified Logs can generate a high volume of events. Enable debug collection on a representative set of hosts, measure volume, and disable **Must backfill** after confirming data flows.

## Additional Notes

- Detection rules that use structured `apple_event.*` fields require Unified Logs integration package version ≥ 0.5.0.
- Minimum Kibana version: 8.19.0.
- Some Unified Log subsystems are suppressed at the OS level and will not emit events even when the integration debug flag is enabled. Those subsystems require an additional host-level `log config` change. See [Apple Events](com_apple_appleevents.md).

## Related Guides

* [Apple Events](com_apple_appleevents.md)

## Related Rules

Use the following GitHub search to identify rules that use Unified Logs:

[Elastic Detection Rules GitHub Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Data+Source%3A+Unified+Logs%22+language%3ATOML&type=code)

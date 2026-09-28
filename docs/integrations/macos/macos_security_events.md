# macOS Security Events Integration

## Setup

Some detection rules require events from the macOS unified log to detect authentication, account management, persistence, and system configuration activity on macOS hosts. These events are collected by the macOS Security Events integration through Elastic Agent. For a description of the integration, its data streams, predicates, and exported fields, refer to the [integration documentation](https://www.elastic.co/docs/reference/integrations/macos). This page covers only the configuration that detection rules depend on.

### Prerequisite Requirements

- Fleet is required for the macOS Security Events integration. To configure Fleet Server refer to the [documentation](https://www.elastic.co/guide/en/fleet/current/fleet-server.html).
- Elastic Agent must be installed and enrolled on the macOS hosts to be monitored.

### Add the integration

- Go to the Kibana home page and click "Add integrations".
- Search for "macOS Security Events", select the integration, and click "Add macOS Security Events".
- Enable the data streams required by the rules you plan to use. Each rule's setup section names the data stream it depends on.
- Assign the integration to the agent policy containing your macOS hosts and click "Save and Continue".

### Host metadata

Documents collected by this integration do not carry `host.*` fields by default. Detection rules that group or correlate by host require them. In each enabled data stream's **Advanced options**, add the following processor:

```
- add_host_metadata:
    netinfo.enabled: false
```

This populates `host.id`, `host.name`, and `host.os.type` on each document.

### Rule-specific configuration

Some rules require additional predicate or log-level changes in a data stream's Advanced options. These are documented per topic:

* [SSH Authentication](macos_security_events_ssh_authentication.md)

## Related Rules

Use the following GitHub search to identify rules that use this integration:

[Elastic Detection Rules Github Repo Search](https://github.com/search?q=repo%3Aelastic%2Fdetection-rules+%22Data+Source%3A+macOS+Security+Events%22+language%3ATOML&type=code)
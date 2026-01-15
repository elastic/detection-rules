# Reintroduction of Defend for Containers Detection Rules in 9.3.0

## Overview

This PR reintroduces the **Elastic Defend for Containers** (`cloud_defend`) detection rules in Elastic Stack version **9.3.0**. The original rules were deprecated in versions 8.18 and 9.0 when the Defend for Containers integration was temporarily sunset. With the integration's revival in 9.3.0, we have carefully reviewed, tuned, and modernized each previously deprecated rule to provide comprehensive container security coverage.

## Background

The Defend for Containers integration provides specialized visibility into containerized environments, offering telemetry from process, file, and alert data sources specific to container workloads. The deprecation in earlier versions left a gap in container-native threat detection that this PR addresses.

## What Changed

### Deprecation Review Process

We conducted a thorough review of all 18 previously deprecated `cloud_defend` rules:

| Deprecated Rule | Status |
|-----------------|--------|
| `container_workload_protection.toml` | Reintroduced |
| `credential_access_aws_creds_search_inside_a_container.toml` | Reintroduced |
| `credential_access_collection_sensitive_files_compression_inside_a_container.toml` | Reintroduced |
| `credential_access_sensitive_keys_or_passwords_search_inside_a_container.toml` | Reintroduced |
| `defense_evasion_ld_preload_shared_object_modified_inside_a_container.toml` | Reintroduced |
| `discovery_suspicious_network_tool_launched_inside_a_container.toml` | Reintroduced |
| `execution_container_management_binary_launched_inside_a_container.toml` | Reintroduced |
| `execution_file_made_executable_via_chmod_inside_a_container.toml` | Reintroduced (renamed) |
| `execution_interactive_exec_to_container.toml` | Reintroduced |
| `execution_interactive_shell_spawned_from_inside_a_container.toml` | Reintroduced |
| `execution_netcat_listener_established_inside_a_container.toml` | Reintroduced |
| `initial_access_ssh_connection_established_inside_a_container.toml` | Not reintroduced |
| `lateral_movement_ssh_process_launched_inside_a_container.toml` | Not reintroduced |
| `persistence_ssh_authorized_keys_modification_inside_a_container.toml` | Reintroduced |
| `privilege_escalation_debugfs_launched_inside_a_privileged_container.toml` | Reintroduced |
| `privilege_escalation_mount_launched_inside_a_privileged_container.toml` | Reintroduced |
| `privilege_escalation_potential_container_escape_via_modified_notify_on_release_file.toml` | Reintroduced |
| `privilege_escalation_potential_container_escape_via_modified_release_agent_file.toml` | Reintroduced |

## Key Improvements and Tunings

### 1. Index Pattern Specificity

**Before (Deprecated):**
```toml
index = ["logs-cloud_defend*"]
```

**After (New):**
```toml
index = ["logs-cloud_defend.process*"]  # For process-based rules
index = ["logs-cloud_defend.file*"]     # For file-based rules
index = ["logs-cloud_defend.alerts-*"]  # For alert forwarding
```

This change improves query performance by targeting specific data streams rather than scanning all cloud_defend indices.

### 2. Enhanced Query Logic

**Example: Interactive Exec Command**

Before:
```eql
process where container.id : "*" and event.type== "start" and
process.entry_leader.entry_meta.type : "container" and
process.entry_leader.same_as_process== true and
process.interactive == true
```

After:
```eql
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
process.entry_leader.entry_meta.type == "container" and
process.entry_leader.same_as_process == true and
process.interactive == true
```

Key improvements:
- Added explicit `host.os.type == "linux"` filter
- Added `event.action == "exec"` for precision
- Specified shell process names for better accuracy

### 3. Risk Score Recalibration

Several rules had their risk scores adjusted based on real-world telemetry and false positive analysis:

| Rule | Old Risk Score | New Risk Score | Old Severity | New Severity |
|------|---------------|----------------|--------------|--------------|
| Interactive Exec Command | 73 (High) | 21 (Low) | High | Low |
| Netcat Listener | 73 (High) | 47 (Medium) | High | Medium |
| Suspicious Network Tool | 47 (Medium) | 21 (Low) | Medium | Low |

The recalibration reflects a more nuanced understanding of container environments where certain activities are common in legitimate workflows.

### 4. False Positive Reduction

**Example: Suspicious Network Tool Rule**

Added exclusions for common benign patterns:
```eql
not (
    process.name in ("nc.traditional", "nc", "ncat", "netcat") and
    process.args like ("-*z*", "localhost", "127.0.0.1")
)
```

This excludes:
- Port scanning with `-z` flag (common health checks)
- Localhost connections (internal diagnostics)

### 5. Expanded Coverage

**Example: Dynamic Linker Modification**

Before:
```eql
file where container.id : "*" and event.type != "deletion" and file.path : "/etc/ld.so.preload"
```

After:
```eql
file where host.os.type == "linux" and event.type != "deletion" and
file.path like ("/etc/ld.so.preload", "/etc/ld.so.conf.d/*", "/etc/ld.so.conf")
```

Now covers additional dynamic linker configuration files that could be abused.

### 6. Investigation Guides

All reintroduced rules include comprehensive investigation guides with:
- **Investigating** section explaining the threat
- **Possible investigation steps** for analysts
- **False positive analysis** guidance
- **Response and remediation** recommendations

## Rules by MITRE ATT&CK Tactic

### Execution (TA0002)
- Container Management Utility Run Inside A Container
- Interactive Exec Command Launched Against A Running Container
- Interactive Shell Spawned From Inside A Container
- Netcat File Transfer or Listener Established Inside A Container
- Suspicious File Made Executable via Chmod Inside A Container

### Credential Access (TA0006)
- AWS Credentials Searched For Inside A Container
- Sensitive File Compression Inside A Container
- Sensitive Keys Or Passwords Searched For Inside A Container

### Privilege Escalation (TA0004)
- Debugfs Launched Inside a Privileged Container
- Mount Launched Inside a Privileged Container
- Potential Container Escape via Modified notify_on_release File
- Potential Container Escape via Modified release_agent File

### Defense Evasion (TA0005)
- Dynamic Linker Modification Inside A Container

### Persistence (TA0003)
- SSH Authorized Keys File Created or Modified Inside a Container

### Discovery (TA0007)
- Suspicious Network Tool Launched Inside A Container

### Container Workload Protection
- Container Workload Protection (alert forwarding rule)

## Data Sources

The rules leverage three primary data sources from the Defend for Containers integration:

| Data Source | Index Pattern | Use Case |
|-------------|--------------|----------|
| Process Events | `logs-cloud_defend.process*` | Process execution monitoring |
| File Events | `logs-cloud_defend.file*` | File system modifications |
| Container Alerts | `logs-cloud_defend.alerts-*` | Integration-generated alerts |

## Minimum Stack Version

All rules require **Elastic Stack 9.3.0** or later:

```toml
[metadata]
min_stack_comments = "Defend for Containers integration was re-introduced in 9.3.0"
min_stack_version = "9.3.0"
```

## Migration Notes

For users upgrading from versions where the deprecated rules were active:

1. **Disable deprecated rules**: The old rules (prefixed with "Deprecated -") should be disabled
2. **Enable new rules**: The reintroduced rules are separate entities and need to be enabled
3. **Review exceptions**: Any exceptions configured for deprecated rules will need to be recreated for the new rules
4. **Update dashboards**: If you have dashboards referencing the old rule IDs, update them to use the new rule names

## Summary

This PR brings back 16 container-focused detection rules with:
- Improved query performance through specific index targeting
- Refined detection logic to reduce false positives
- Recalibrated risk scores based on operational feedback
- Extended coverage for emerging container attack techniques
- Comprehensive investigation guides for security analysts

The reintroduction ensures that Elastic Security customers can once again leverage purpose-built detection capabilities for their containerized workloads.

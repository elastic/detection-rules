# Windows Audit Policies

Windows related audit policies that need to be implemented in order to generate the events that power our detection rules. It serves as a centralized view of the policies we use so you don't need to go through every rule to know the different audit policies required.

Audit Policies:

* [Audit Authorization Policy Change](audit_authorization_policy_change.md)
* [Audit Computer Account Management](audit_computer_account_management.md)
* [Audit Detailed File Share](audit_detailed_file_share.md)
* [Audit Directory Service Access](audit_directory_service_access.md)
* [Audit Directory Service Changes](audit_directory_service_changes.md)
* [Audit Filtering Platform Connection](audit_filtering_platform_connection.md)
* [Audit Filtering Platform Packet Drop](audit_filtering_platform_packet_drop.md)
* [Audit Handle Manipulation](audit_handle_manipulation.md)
* [Audit Logon](audit_logon.md)
* [Audit Other Object Access Events](audit_other_object_access_events.md)
* [Audit Policy Change](audit_policy_change.md)
* [Audit Process Creation and Command Line](audit_process_creation_and_command_line.md)
* [Audit Security Group Management](audit_security_group_management.md)
* [Audit Security System Extension](audit_security_system_extension.md)
* [Audit Sensitive Privilege Use](audit_sensitive_privilege_use.md)
* [Audit Special Logon](audit_special_logon.md)
* [Audit Token Right Adjusted Events](audit_token_right_adjusted_events.md)
* [Audit User Account Management](audit_user_account_management.md)
* [Audit Powershell Script Block Logging](audit_powershell_scriptblock.md)

---

# Sysmon Configuration Guides

**Caution:** The following guides provide minimal configuration examples designed to enable specific Sysmon Event IDs. Collecting Sysmon events without a tailored configuration for your environment will cause high data volume and potentially high CPU-load, and these setup instructions require significant tuning to be production-ready.

To build an efficient and production-ready configuration, we strongly recommend exploring these community resources:

 - [TrustedSec Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide)
 - [olafhartong - sysmon-modular](https://github.com/olafhartong/sysmon-modular)
 - [Neo23x0 - sysmon-config](https://github.com/Neo23x0/sysmon-config)

For a production-ready and more integrated solution that is designed to work with our detection rules and also provide native Endpoint Protection and Response, check out [Elastic Endpoint Security](https://www.elastic.co/security/endpoint-security).

* [Sysmon Event ID 1: Process Creation](sysmon_eventid1_process_creation.md)
* [Sysmon Event ID 2: File Creation Time Changed](sysmon_eventid2_file_creation_time_changed.md)
* [Sysmon Event ID 3: Network Connection](sysmon_eventid3_network_connection.md)
* [Sysmon Event ID 7: Image Loaded](sysmon_eventid7_image_loaded.md)
* [Sysmon Event ID 8: Create Remote Thread](sysmon_eventid8_createremotethread.md)
* [Sysmon Event ID 10: Process Accessed](sysmon_eventid10_process_access.md)
* [Sysmon Event ID 11: File Create](sysmon_eventid11_file_create.md)
* [Sysmon Event IDs 12, 13, 14: Registry Events](sysmon_eventid12_13_14_registry_event.md)
* [Sysmon Event IDs 17, 18: Named Pipe Events](sysmon_eventid17_18_pipe_event.md)
* [Sysmon Event IDs 19, 20, 21: WMI Events](sysmon_eventid19_20_21_wmi_event.md)
* [Sysmon Event ID 22: DNS Query](sysmon_eventid22_dns_query.md)
* [Sysmon Event ID 23: File Delete](sysmon_eventid23_file_delete.md)

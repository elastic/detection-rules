# Documents generation from detection rules

This report captures the error reported while generating documents from detection rules. Here you
can learn what rules are still problematic and for which no documents can be generated at the moment.

Curious about the inner workings? Read [here](signals_generation.md).

## Table of contents
   1. [Skipped rules](#skipped-rules)
      1. [Unsupported rule type: machine_learning](#unsupported-rule-type-machine_learning)
      1. [Unsupported rule type: threshold](#unsupported-rule-type-threshold)
      1. [Unsupported query language: lucene](#unsupported-query-language-lucene)
      1. [Unsupported rule type: threat_match](#unsupported-rule-type-threat_match)
   1. [Generation errors](#generation-errors)
      1. [Constraints solver not implemented: wildcard](#constraints-solver-not-implemented-wildcard)
      1. [Unsupported function: match](#unsupported-function-match)
      1. [Cannot trigger with any document](#cannot-trigger-with-any-document)
      1. [Unsupported LHS type: <class 'eql.ast.FunctionCall'>](#unsupported-lhs-type-class-eqlastfunctioncall)
      1. [Unsolvable constraints ==: powershell.file.script_block_text (is already 'waveInGetNumDevs', cannot set to 'mciSendStringA')](#unsolvable-constraints--powershellfilescript_block_text-is-already-waveingetnumdevs-cannot-set-to-mcisendstringa)
      1. [Constraints solver not implemented: match_only_text](#constraints-solver-not-implemented-match_only_text)
      1. [Unsolvable constraints: process.name (wildcard(s) both included and excluded: 'rundll32.exe')](#unsolvable-constraints-processname-wildcards-both-included-and-excluded-rundll32exe)

## Skipped rules

### Unsupported rule type: machine_learning

50 rules:

* [Anomalous Kernel Module Activity](../../rules/ml/ml_linux_anomalous_kernel_module_arguments.toml)
* [Anomalous Linux Compiler Activity](../../rules/ml/ml_linux_anomalous_compiler_activity.toml)
* [Anomalous Process For a Linux Population](../../rules/ml/ml_linux_anomalous_process_all_hosts.toml)
* [Anomalous Process For a Windows Population](../../rules/ml/ml_windows_anomalous_process_all_hosts.toml)
* [Anomalous Windows Process Creation](../../rules/ml/ml_windows_anomalous_process_creation.toml)
* [DNS Tunneling](../../rules/ml/ml_packetbeat_dns_tunneling.toml)
* [Network Traffic to Rare Destination Country](../../rules/ml/ml_rare_destination_country.toml)
* [Rare AWS Error Code](../../rules/integrations/aws/ml_cloudtrail_rare_error_code.toml)
* [Rare User Logon](../../rules/ml/ml_auth_rare_user_logon.toml)
* [Spike in AWS Error Messages](../../rules/integrations/aws/ml_cloudtrail_error_message_spike.toml)
* [Spike in Failed Logon Events](../../rules/ml/ml_auth_spike_in_failed_logon_events.toml)
* [Spike in Firewall Denies](../../rules/ml/ml_high_count_network_denies.toml)
* [Spike in Logon Events from a Source IP](../../rules/ml/ml_auth_spike_in_logon_events_from_a_source_ip.toml)
* [Spike in Logon Events](../../rules/ml/ml_auth_spike_in_logon_events.toml)
* [Spike in Network Traffic To a Country](../../rules/ml/ml_spike_in_traffic_to_a_country.toml)
* [Spike in Network Traffic](../../rules/ml/ml_high_count_network_events.toml)
* [Suspicious Powershell Script](../../rules/ml/ml_windows_anomalous_script.toml)
* [Unusual AWS Command for a User](../../rules/integrations/aws/ml_cloudtrail_rare_method_by_user.toml)
* [Unusual City For an AWS Command](../../rules/integrations/aws/ml_cloudtrail_rare_method_by_city.toml)
* [Unusual Country For an AWS Command](../../rules/integrations/aws/ml_cloudtrail_rare_method_by_country.toml)
* [Unusual DNS Activity](../../rules/ml/ml_packetbeat_rare_dns_question.toml)
* [Unusual Hour for a User to Logon](../../rules/ml/ml_auth_rare_hour_for_a_user_to_logon.toml)
* [Unusual Linux Network Activity](../../rules/ml/ml_linux_anomalous_network_activity.toml)
* [Unusual Linux Network Connection Discovery](../../rules/ml/ml_linux_system_network_connection_discovery.toml)
* [Unusual Linux Network Port Activity](../../rules/ml/ml_linux_anomalous_network_port_activity.toml)
* [Unusual Linux Network Service](../../rules/ml/ml_linux_anomalous_network_service.toml)
* [Unusual Linux Process Calling the Metadata Service](../../rules/ml/ml_linux_anomalous_metadata_process.toml)
* [Unusual Linux Process Discovery Activity](../../rules/ml/ml_linux_system_process_discovery.toml)
* [Unusual Linux System Information Discovery Activity](../../rules/ml/ml_linux_system_information_discovery.toml)
* [Unusual Linux System Network Configuration Discovery](../../rules/ml/ml_linux_system_network_configuration_discovery.toml)
* [Unusual Linux System Owner or User Discovery Activity](../../rules/ml/ml_linux_system_user_discovery.toml)
* [Unusual Linux User Calling the Metadata Service](../../rules/ml/ml_linux_anomalous_metadata_user.toml)
* [Unusual Linux Username](../../rules/ml/ml_linux_anomalous_user_name.toml)
* [Unusual Linux Web Activity](../../rules/ml/ml_linux_anomalous_network_url_activity.toml)
* [Unusual Login Activity](../../rules/ml/ml_suspicious_login_activity.toml)
* [Unusual Network Destination Domain Name](../../rules/ml/ml_packetbeat_rare_server_domain.toml)
* [Unusual Process For a Linux Host](../../rules/ml/ml_rare_process_by_host_linux.toml)
* [Unusual Process For a Windows Host](../../rules/ml/ml_rare_process_by_host_windows.toml)
* [Unusual Source IP for a User to Logon from](../../rules/ml/ml_auth_rare_source_ip_for_a_user.toml)
* [Unusual Sudo Activity](../../rules/ml/ml_linux_anomalous_sudo_activity.toml)
* [Unusual Web Request](../../rules/ml/ml_packetbeat_rare_urls.toml)
* [Unusual Web User Agent](../../rules/ml/ml_packetbeat_rare_user_agent.toml)
* [Unusual Windows Network Activity](../../rules/ml/ml_windows_anomalous_network_activity.toml)
* [Unusual Windows Path Activity](../../rules/ml/ml_windows_anomalous_path_activity.toml)
* [Unusual Windows Process Calling the Metadata Service](../../rules/ml/ml_windows_anomalous_metadata_process.toml)
* [Unusual Windows Remote User](../../rules/ml/ml_windows_rare_user_type10_remote_login.toml)
* [Unusual Windows Service](../../rules/ml/ml_windows_anomalous_service.toml)
* [Unusual Windows User Calling the Metadata Service](../../rules/ml/ml_windows_anomalous_metadata_user.toml)
* [Unusual Windows User Privilege Elevation Activity](../../rules/ml/ml_windows_rare_user_runas_event.toml)
* [Unusual Windows Username](../../rules/ml/ml_windows_anomalous_user_name.toml)

### Unsupported rule type: threshold

14 rules:

* [AWS IAM Brute Force of Assume Role Policy](../../rules/integrations/aws/credential_access_aws_iam_assume_role_brute_force.toml)
* [AWS Management Console Brute Force of Root User Identity](../../rules/integrations/aws/credential_access_root_console_failure_brute_force.toml)
* [Agent Spoofing - Multiple Hosts Using Same Agent](../../rules/cross-platform/defense_evasion_agent_spoofing_multiple_hosts.toml)
* [Attempts to Brute Force a Microsoft 365 User Account](../../rules/integrations/o365/credential_access_microsoft_365_brute_force_user_account_attempt.toml)
* [Attempts to Brute Force an Okta User Account](../../rules/integrations/okta/credential_access_attempts_to_brute_force_okta_user_account.toml)
* [High Number of Okta User Password Reset or Unlock Attempts](../../rules/integrations/okta/defense_evasion_suspicious_okta_user_password_reset_or_unlock_attempts.toml)
* [High Number of Process and/or Service Terminations](../../rules/windows/impact_stop_process_service_threshold.toml)
* [O365 Excessive Single Sign-On Logon Errors](../../rules/integrations/o365/credential_access_user_excessive_sso_logon_errors.toml)
* [Okta Brute Force or Password Spraying Attack](../../rules/integrations/okta/credential_access_okta_brute_force_or_password_spraying.toml)
* [Potential DNS Tunneling via NsLookup](../../rules/windows/command_and_control_dns_tunneling_nslookup.toml)
* [Potential LSASS Memory Dump via PssCaptureSnapShot](../../rules/windows/credential_access_suspicious_lsass_access_via_snapshot.toml)
* [Potential Password Spraying of Microsoft 365 User Accounts](../../rules/integrations/o365/credential_access_microsoft_365_potential_password_spraying_attack.toml)
* [Potential SSH Brute Force Detected](../../rules/macos/credential_access_potential_ssh_bruteforce.toml)
* [Sudo Heap-Based Buffer Overflow Attempt](../../rules/cross-platform/privilege_escalation_sudo_buffer_overflow.toml)

### Unsupported query language: lucene

6 rules:

* [Cobalt Strike Command and Control Beacon](../../rules/network/command_and_control_cobalt_strike_beacon.toml)
* [Halfbaked Command and Control Beacon](../../rules/network/command_and_control_halfbaked_beacon.toml)
* [Inbound Connection to an Unsecure Elasticsearch Node](../../rules/network/initial_access_unsecure_elasticsearch_node.toml)
* [Possible FIN7 DGA Command and Control Behavior](../../rules/network/command_and_control_fin7_c2_behavior.toml)
* [Roshal Archive (RAR) or PowerShell File Downloaded from the Internet](../../rules/network/command_and_control_download_rar_powershell_from_internet.toml)
* [Setuid / Setgid Bit Set via chmod](../../rules/cross-platform/privilege_escalation_setuid_setgid_bit_set_via_chmod.toml)

### Unsupported rule type: threat_match

3 rules:

* [Threat Intel Filebeat Module (v7.x) Indicator Match](../../rules/cross-platform/threat_intel_filebeat7x.toml)
* [Threat Intel Filebeat Module (v8.x) Indicator Match](../../rules/cross-platform/threat_intel_filebeat8x.toml)
* [Threat Intel Indicator Match](../../rules/cross-platform/threat_intel_fleet_integrations.toml)

## Generation errors

### Constraints solver not implemented: wildcard

39 rules:
* [Apple Scripting Execution with Administrator Privileges](../../rules/macos/privilege_escalation_applescript_with_admin_privs.toml)
* [Attempt to Mount SMB Share via Command Line](../../rules/macos/lateral_movement_mounting_smb_share.toml)
* [Attempt to Remove File Quarantine Attribute](../../rules/macos/defense_evasion_attempt_del_quarantine_attrib.toml)
* [Command Shell Activity Started via RunDLL32](../../rules/windows/execution_command_shell_via_rundll32.toml)
* [Component Object Model Hijacking](../../rules/windows/persistence_suspicious_com_hijack_registry.toml)
* [Control Panel Process with Unusual Arguments](../../rules/windows/defense_evasion_execution_control_panel_suspicious_args.toml)
* [Creation of Hidden Login Item via Apple Script](../../rules/macos/persistence_creation_hidden_login_item_osascript.toml)
* [DNS-over-HTTPS Enabled via Registry](../../rules/windows/defense_evasion_dns_over_https_enabled.toml)
* [Disabling User Account Control via Registry Modification](../../rules/windows/privilege_escalation_disable_uac_registry.toml)
* [Encoded Executable Stored in the Registry](../../rules/windows/defense_evasion_hide_encoded_executable_registry.toml)
* [Modification of AmsiEnable Registry Key](../../rules/windows/defense_evasion_amsienable_key_mod.toml)
* [Modification of WDigest Security Provider](../../rules/windows/credential_access_mod_wdigest_security_provider.toml)
* [Network Logon Provider Registry Modification](../../rules/windows/credential_access_persistence_network_logon_provider_modification.toml)
* [NullSessionPipe Registry Modification](../../rules/windows/lateral_movement_defense_evasion_lanman_nullsessionpipe_modification.toml)
* [Persistence via WMI Standard Registry Provider](../../rules/windows/persistence_via_wmi_stdregprov_run_services.toml)
* [Potential Persistence via Time Provider Modification](../../rules/windows/persistence_time_provider_mod.toml)
* [Potential Port Monitor or Print Processor Registration Abuse](../../rules/windows/privilege_escalation_port_monitor_print_pocessor_abuse.toml)
* [Potential PrintNightmare Exploit Registry Modification](../../rules/windows/privilege_escalation_printspooler_malicious_registry_modification.toml)
* [Potential Privacy Control Bypass via Localhost Secure Copy](../../rules/macos/defense_evasion_privilege_escalation_privacy_pref_sshd_fulldiskaccess.toml)
* [Potential SharpRDP Behavior](../../rules/windows/lateral_movement_rdp_sharprdp_target.toml)
* [Privilege Escalation via Windir Environment Variable](../../rules/windows/privilege_escalation_rogue_windir_environment_var.toml)
* [Prompt for Credentials with OSASCRIPT](../../rules/macos/credential_access_promt_for_pwd_via_osascript.toml)
* [RDP Enabled via Registry](../../rules/windows/lateral_movement_rdp_enabled_registry.toml)
* [SIP Provider Modification](../../rules/windows/defense_evasion_sip_provider_mod.toml)
* [SUNBURST Command and Control Activity](../../rules/windows/command_and_control_sunburst_c2_activity_detected.toml)
* [Scheduled Tasks AT Command Enabled](../../rules/windows/defense_evasion_scheduledjobs_at_protocol_enabled.toml)
* [SolarWinds Process Disabling Services via Registry](../../rules/windows/defense_evasion_solarwinds_backdoor_service_disabled_via_registry.toml)
* [Startup or Run Key Registry Modification](../../rules/windows/persistence_run_key_and_startup_broad.toml)
* [Suspicious Browser Child Process](../../rules/macos/execution_initial_access_suspicious_browser_childproc.toml)
* [Suspicious ImagePath Service Creation](../../rules/windows/persistence_suspicious_service_created_registry.toml)
* [Suspicious Print Spooler Point and Print DLL](../../rules/windows/privilege_escalation_printspooler_registry_copyfiles.toml)
* [Suspicious Startup Shell Folder Modification](../../rules/windows/persistence_evasion_registry_startup_shell_folder_modified.toml)
* [Suspicious WMIC XSL Script Execution](../../rules/windows/defense_evasion_suspicious_wmi_script.toml)
* [Uncommon Registry Persistence Change](../../rules/windows/persistence_registry_uncommon.toml)
* [Unusual Persistence via Services Registry](../../rules/windows/persistence_services_registry.toml)
* [Unusual Print Spooler Child Process](../../rules/windows/privilege_escalation_unusual_printspooler_childprocess.toml)
* [Virtual Private Network Connection Attempt](../../rules/macos/lateral_movement_vpn_connection_attempt.toml)
* [Web Application Suspicious Activity: No User Agent](../../rules/apm/apm_null_user_agent.toml)
* [Windows Defender Disabled via Registry Modification](../../rules/windows/defense_evasion_defender_disabled_via_registry.toml)

### Unsupported function: match

5 rules:
* [Creation of Hidden Files and Directories](../../rules/linux/defense_evasion_hidden_file_dir_tmp.toml)
* [Executable File Creation with Multiple Extensions](../../rules/windows/defense_evasion_file_creation_mult_extension.toml)
* [Potential Credential Access via Windows Utilities](../../rules/windows/credential_access_cmdline_dump_tool.toml)
* [Suspicious PowerShell Engine ImageLoad](../../rules/windows/execution_suspicious_powershell_imgload.toml)
* [Whitespace Padding in Process Command Line](../../rules/windows/defense_evasion_whitespace_padding_in_command_line.toml)

### Cannot trigger with any document

5 rules:
* [Persistence via Login or Logout Hook](../../rules/macos/persistence_login_logout_hooks_defaults.toml)
* [Potential Admin Group Account Addition](../../rules/macos/privilege_escalation_local_user_added_to_admin.toml)
* [Potential Hidden Local User Account Creation](../../rules/macos/persistence_account_creation_hide_at_logon.toml)
* [Potential Process Injection via PowerShell](../../rules/windows/defense_evasion_posh_process_injection.toml)
* [SoftwareUpdate Preferences Modification](../../rules/macos/defense_evasion_apple_softupdates_modification.toml)

### Unsupported LHS type: <class 'eql.ast.FunctionCall'>

3 rules:
* [Image File Execution Options Injection](../../rules/windows/persistence_evasion_registry_ifeo_injection.toml)
* [Suspicious Execution - Short Program Name](../../rules/windows/execution_suspicious_short_program_name.toml)
* [Suspicious Process Access via Direct System Call](../../rules/windows/defense_evasion_suspicious_process_access_direct_syscall.toml)

### Unsolvable constraints ==: powershell.file.script_block_text (is already 'waveInGetNumDevs', cannot set to 'mciSendStringA')

1 rules:
* [PowerShell Suspicious Script with Audio Capture Capabilities](../../rules/windows/collection_posh_audio_capture.toml)

### Constraints solver not implemented: match_only_text

1 rules:
* [Windows CryptoAPI Spoofing Vulnerability (CVE-2020-0601 - CurveBall)](../../rules/windows/defense_evasion_cve_2020_0601.toml)

### Unsolvable constraints: process.name (wildcard(s) both included and excluded: 'rundll32.exe')

1 rules:
* [Execution from Unusual Directory - Command Line](../../rules/windows/execution_from_unusual_path_cmdline.toml)

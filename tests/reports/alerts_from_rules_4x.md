# Alerts generation from detection rules

This report captures the detection rules signals generation coverage. Here you can
learn what rules are supported and what not and why.

Curious about the inner workings? Read [here](signals_generation.md).

This report was generated with a multiplying factor of 4.

## Table of contents
   1. [Rules with no signals (25)](#rules-with-no-signals-25)
   1. [Rules with too few signals (5)](#rules-with-too-few-signals-5)
   1. [Rules with the correct signals (506)](#rules-with-the-correct-signals-506)

## Rules with no signals (25)

### AdminSDHolder Backdoor

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-598

### Authorization Plugin Modification

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-292

### Azure AD Global Administrator Role Assigned

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-115

### Azure External Guest User Invitation

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-110

### Azure Full Network Packet Capture Detected

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-086

### Azure Global Administrator Role Addition to PIM User

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-116

### GCP IAM Custom Role Creation

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-144

### GCP IAM Role Deletion

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-137

### GCP IAM Service Account Key Deletion

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-145

### GCP Logging Bucket Deletion

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-130

### GCP Logging Sink Deletion

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-131

### GCP Logging Sink Modification

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-136

### GCP Pub/Sub Subscription Creation

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-125

### GCP Pub/Sub Subscription Deletion

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-132

### GCP Pub/Sub Topic Creation

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-126

### GCP Pub/Sub Topic Deletion

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-133

### GCP Service Account Creation

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-147

### GCP Service Account Deletion

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-138

### GCP Service Account Disabled

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-139

### GCP Service Account Key Creation

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-146

### LaunchDaemon Creation or Modification and Immediate Loading

Branch count: 16  
Document count: 32  
Index: detection-rules-ut-291

### Persistence via DirectoryService Plugin Modification

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-294

### Persistence via Docker Shortcut Modification

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-295

### Potential Persistence via Atom Init Script Modification

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-309

### Suspicious Calendar File Modification

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-308

## Rules with too few signals (5)

### Execution of Persistent Suspicious Program

Branch count: 288  
Document count: 864  
Index: detection-rules-ut-618

### File and Directory Discovery

Branch count: 500  
Document count: 1500  
Index: detection-rules-ut-518

### Persistence via Folder Action Script

Branch count: 264  
Document count: 528  
Index: detection-rules-ut-301

### Sensitive Files Compression

Branch count: 380  
Document count: 380  
Index: detection-rules-ut-218

### Unusual Parent-Child Relationship

Branch count: 192  
Document count: 192  
Index: detection-rules-ut-667

## Rules with the correct signals (506)

### AWS Access Secret in Secrets Manager

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-031

### AWS CloudTrail Log Created

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-027

### AWS CloudTrail Log Deleted

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-032

### AWS CloudTrail Log Suspended

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-033

### AWS CloudTrail Log Updated

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-051

### AWS CloudWatch Alarm Deletion

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-034

### AWS CloudWatch Log Group Deletion

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-052

### AWS CloudWatch Log Stream Deletion

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-053

### AWS Config Service Tampering

Branch count: 36  
Document count: 36  
Index: detection-rules-ut-035

### AWS Configuration Recorder Stopped

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-036

### AWS EC2 Encryption Disabled

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-054

### AWS EC2 Flow Log Deletion

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-037

### AWS EC2 Full Network Packet Capture Detected

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-045

### AWS EC2 Network Access Control List Creation

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-069

### AWS EC2 Network Access Control List Deletion

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-038

### AWS EC2 Snapshot Activity

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-046

### AWS EC2 VM Export Failure

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-047

### AWS EFS File System or Mount Deleted

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-055

### AWS ElastiCache Security Group Created

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-039

### AWS ElastiCache Security Group Modified or Deleted

Branch count: 20  
Document count: 20  
Index: detection-rules-ut-040

### AWS EventBridge Rule Disabled or Deleted

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-050

### AWS Execution via System Manager

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-063

### AWS GuardDuty Detector Deletion

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-041

### AWS IAM Assume Role Policy Update

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-084

### AWS IAM Deactivation of MFA Device

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-056

### AWS IAM Group Creation

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-071

### AWS IAM Group Deletion

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-057

### AWS IAM Password Recovery Requested

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-062

### AWS IAM User Addition to Group

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-029

### AWS Management Console Root Login

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-061

### AWS RDS Cluster Creation

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-072

### AWS RDS Cluster Deletion

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-058

### AWS RDS Instance Creation

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-074

### AWS RDS Instance/Cluster Stoppage

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-060

### AWS RDS Security Group Creation

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-073

### AWS RDS Security Group Deletion

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-059

### AWS RDS Snapshot Export

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-048

### AWS RDS Snapshot Restored

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-049

### AWS Root Login Without MFA

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-081

### AWS Route 53 Domain Transfer Lock Disabled

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-075

### AWS Route 53 Domain Transferred to Another Account

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-076

### AWS Route Table Created

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-078

### AWS Route Table Modified or Deleted

Branch count: 20  
Document count: 20  
Index: detection-rules-ut-079

### AWS Route53 private hosted zone associated with a VPC

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-077

### AWS S3 Bucket Configuration Deletion

Branch count: 20  
Document count: 20  
Index: detection-rules-ut-042

### AWS SAML Activity

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-080

### AWS STS GetSessionToken Abuse

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-083

### AWS Security Group Configuration Change Detection

Branch count: 24  
Document count: 24  
Index: detection-rules-ut-070

### AWS Security Token Service (STS) AssumeRole Usage

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-082

### AWS WAF Access Control List Deletion

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-043

### AWS WAF Rule or Rule Group Deletion

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-044

### Abnormally Large DNS Response

Branch count: 24  
Document count: 24  
Index: detection-rules-ut-581

### Access of Stored Browser Credentials

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-255

### Access to Keychain Credentials Directories

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-256

### Account Password Reset Remotely

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-616

### AdFind Command Activity

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-516

### Adding Hidden File Attribute via Attrib

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-439

### Administrator Privileges Assigned to an Okta Group

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-212

### Administrator Role Assigned to an Okta User

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-213

### Adobe Hijack Persistence

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-599

### Adversary Behavior - Detected - Elastic Endgame

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-376

### Agent Spoofing - Mismatched Agent ID

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-005

### Apple Script Execution followed by Network Connection

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-281

### Application Added to Google Workspace Domain

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-149

### Attempt to Create Okta API Token

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-214

### Attempt to Deactivate MFA for an Okta User Account

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-215

### Attempt to Deactivate an Okta Application

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-200

### Attempt to Deactivate an Okta Network Zone

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-189

### Attempt to Deactivate an Okta Policy

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-201

### Attempt to Deactivate an Okta Policy Rule

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-202

### Attempt to Delete an Okta Application

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-203

### Attempt to Delete an Okta Network Zone

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-190

### Attempt to Delete an Okta Policy

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-204

### Attempt to Delete an Okta Policy Rule

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-205

### Attempt to Disable Gatekeeper

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-267

### Attempt to Disable IPTables or Firewall

Branch count: 84  
Document count: 84  
Index: detection-rules-ut-221

### Attempt to Disable Syslog Service

Branch count: 120  
Document count: 120  
Index: detection-rules-ut-222

### Attempt to Enable the Root Account

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-298

### Attempt to Install Root Certificate

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-268

### Attempt to Modify an Okta Application

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-206

### Attempt to Modify an Okta Network Zone

Branch count: 12  
Document count: 12  
Index: detection-rules-ut-207

### Attempt to Modify an Okta Policy

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-208

### Attempt to Modify an Okta Policy Rule

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-209

### Attempt to Reset MFA Factors for an Okta User Account

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-216

### Attempt to Revoke Okta API Token

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-196

### Attempt to Unload Elastic Endpoint Security Kernel Extension

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-275

### Attempted Bypass of Okta MFA

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-191

### Auditd Login Attempt at Forbidden Time

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-241

### Auditd Login from Forbidden Location

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-239

### Auditd Max Failed Login Attempts

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-238

### Auditd Max Login Sessions

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-240

### Azure Active Directory High Risk Sign-in

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-106

### Azure Active Directory High Risk User Sign-in Heuristic

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-107

### Azure Active Directory PowerShell Sign-in

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-108

### Azure Alert Suppression Rule Created or Modified

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-098

### Azure Application Credential Modification

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-089

### Azure Automation Account Created

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-111

### Azure Automation Runbook Created or Modified

Branch count: 24  
Document count: 24  
Index: detection-rules-ut-112

### Azure Automation Runbook Deleted

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-101

### Azure Automation Webhook Created

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-113

### Azure Blob Container Access Level Modification

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-099

### Azure Blob Permissions Modification

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-090

### Azure Command Execution on Virtual Machine

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-100

### Azure Conditional Access Policy Modified

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-114

### Azure Diagnostic Settings Deletion

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-091

### Azure Event Hub Authorization Rule Created or Updated

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-085

### Azure Event Hub Deletion

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-093

### Azure Firewall Policy Deletion

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-094

### Azure Frontdoor Web Application Firewall (WAF) Policy Deleted

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-095

### Azure Key Vault Modified

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-087

### Azure Kubernetes Events Deleted

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-096

### Azure Kubernetes Pods Deleted

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-103

### Azure Kubernetes Rolebindings Created

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-121

### Azure Network Watcher Deletion

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-097

### Azure Privilege Identity Management Role Modified

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-117

### Azure Resource Group Deletion

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-104

### Azure Service Principal Addition

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-092

### Azure Service Principal Credentials Added

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-102

### Azure Storage Account Key Regenerated

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-088

### Azure Virtual Network Device Modified or Deleted

Branch count: 88  
Document count: 88  
Index: detection-rules-ut-105

### Base16 or Base32 Encoding/Decoding Activity

Branch count: 32  
Document count: 32  
Index: detection-rules-ut-224

### Bash Shell Profile Modification

Branch count: 12  
Document count: 12  
Index: detection-rules-ut-019

### Bypass UAC via Event Viewer

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-663

### Bypass UAC via Sdclt

Branch count: 16  
Document count: 32  
Index: detection-rules-ut-666

### Clearing Windows Console History

Branch count: 24  
Document count: 24  
Index: detection-rules-ut-441

### Clearing Windows Event Logs

Branch count: 20  
Document count: 20  
Index: detection-rules-ut-442

### Command Execution via SolarWinds Process

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-528

### Command Prompt Network Connection

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-531

### Conhost Spawned By Suspicious Parent Process

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-556

### Connection to Commonly Abused Free SSL Certificate Providers

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-400

### Connection to Commonly Abused Web Services

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-398

### Connection to External Network via Telnet

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-242

### Connection to Internal Network via Telnet

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-243

### Creation of Hidden Launch Agent or Daemon

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-299

### Creation of a Hidden Local User Account

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-603

### Creation of a local user account

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-631

### Creation or Modification of Domain Backup DPAPI private key

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-415

### Creation or Modification of Root Certificate

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-445

### Creation or Modification of a new GPO Scheduled Task or Service

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-606

### Credential Acquisition via Registry Hive Dumping

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-416

### Credential Dumping - Detected - Elastic Endgame

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-377

### Credential Dumping - Prevented - Elastic Endgame

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-378

### Credential Manipulation - Detected - Elastic Endgame

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-379

### Credential Manipulation - Prevented - Elastic Endgame

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-380

### CyberArk Privileged Access Security Error

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-122

### CyberArk Privileged Access Security Recommended Monitor

Branch count: 80  
Document count: 80  
Index: detection-rules-ut-123

### DNS Activity to the Internet

Branch count: 96  
Document count: 96  
Index: detection-rules-ut-362

### Default Cobalt Strike Team Server Certificate

Branch count: 24  
Document count: 24  
Index: detection-rules-ut-361

### Delete Volume USN Journal with Fsutil

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-449

### Deleting Backup Catalogs with Wbadmin

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-559

### Direct Outbound SMB Connection

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-580

### Disable Windows Event and Security Logs Using Built-in Tools

Branch count: 40  
Document count: 40  
Index: detection-rules-ut-453

### Disable Windows Firewall Rules via Netsh

Branch count: 12  
Document count: 12  
Index: detection-rules-ut-451

### Disabling Windows Defender Security Settings via PowerShell

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-452

### Domain Added to Google Workspace Trusted Domains

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-150

### Downloaded Shortcut Files

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-535

### Downloaded URL Files

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-536

### Dumping Account Hashes via Built-In Commands

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-257

### Dumping of Keychain Content via Security Command

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-258

### EggShell Backdoor Execution

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-011

### Emond Rules Creation or Modification

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-296

### Enable Host Network Discovery via Netsh

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-457

### Encrypting Files with WinRar or 7z

Branch count: 32  
Document count: 32  
Index: detection-rules-ut-396

### Endpoint Security

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-124

### Enumeration Command Spawned via WMIPrvSE

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-537

### Enumeration of Administrator Accounts

Branch count: 40  
Document count: 40  
Index: detection-rules-ut-517

### Enumeration of Kernel Modules

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-234

### Enumeration of Privileged Local Groups Membership

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-524

### Enumeration of Users or Groups via Built-in Commands

Branch count: 12  
Document count: 12  
Index: detection-rules-ut-276

### Execution of COM object via Xwizard

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-530

### Execution of File Written or Modified by Microsoft Office

Branch count: 8  
Document count: 16  
Index: detection-rules-ut-541

### Execution of File Written or Modified by PDF Reader

Branch count: 8  
Document count: 16  
Index: detection-rules-ut-542

### Execution via Electron Child Process Node.js Module

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-277

### Execution via MSSQL xp_cmdshell Stored Procedure

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-557

### Execution via TSClient Mountpoint

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-584

### Execution via local SxS Shared Module

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-548

### Execution with Explicit Credentials via Scripting

Branch count: 72  
Document count: 72  
Index: detection-rules-ut-311

### Exploit - Detected - Elastic Endgame

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-381

### Exploit - Prevented - Elastic Endgame

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-382

### Exporting Exchange Mailbox via PowerShell

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-392

### External Alerts

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-391

### External IP Lookup from Non-Browser Process

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-523

### File Deletion via Shred

Branch count: 32  
Document count: 32  
Index: detection-rules-ut-228

### File Permission Modification in Writable Directory

Branch count: 96  
Document count: 96  
Index: detection-rules-ut-229

### Finder Sync Plugin Registered and Enabled

Branch count: 16  
Document count: 32  
Index: detection-rules-ut-300

### GCP Firewall Rule Creation

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-127

### GCP Firewall Rule Deletion

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-128

### GCP Firewall Rule Modification

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-129

### GCP Kubernetes Rolebindings Created or Patched

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-148

### GCP Storage Bucket Configuration Modification

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-134

### GCP Storage Bucket Deletion

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-140

### GCP Storage Bucket Permissions Modification

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-135

### GCP Virtual Private Cloud Network Deletion

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-141

### GCP Virtual Private Cloud Route Creation

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-142

### GCP Virtual Private Cloud Route Deletion

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-143

### Google Workspace API Access Granted via Domain-Wide Delegation of Authority

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-156

### Google Workspace Admin Role Assigned to a User

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-155

### Google Workspace Admin Role Deletion

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-151

### Google Workspace Custom Admin Role Created

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-157

### Google Workspace MFA Enforcement Disabled

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-152

### Google Workspace Password Policy Modified

Branch count: 48  
Document count: 48  
Index: detection-rules-ut-153

### Google Workspace Role Modified

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-158

### Hosts File Modified

Branch count: 32  
Document count: 32  
Index: detection-rules-ut-016

### Hping Process Activity

Branch count: 24  
Document count: 24  
Index: detection-rules-ut-244

### IIS HTTP Logging Disabled

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-469

### IPSEC NAT Traversal Port Activity

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-366

### ImageLoad via Windows Update Auto Update Client

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-459

### Incoming DCOM Lateral Movement via MSHTA

Branch count: 8  
Document count: 16  
Index: detection-rules-ut-576

### Incoming DCOM Lateral Movement with MMC

Branch count: 8  
Document count: 16  
Index: detection-rules-ut-577

### Incoming DCOM Lateral Movement with ShellBrowserWindow or ShellWindows

Branch count: 8  
Document count: 16  
Index: detection-rules-ut-578

### Incoming Execution via PowerShell Remoting

Branch count: 8  
Document count: 16  
Index: detection-rules-ut-589

### Incoming Execution via WinRM Remote Shell

Branch count: 8  
Document count: 16  
Index: detection-rules-ut-586

### InstallUtil Process Making Network Connections

Branch count: 8  
Document count: 16  
Index: detection-rules-ut-471

### Installation of Custom Shim Databases

Branch count: 32  
Document count: 64  
Index: detection-rules-ut-600

### Installation of Security Support Provider

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-635

### Interactive Terminal Spawned via Perl

Branch count: 24  
Document count: 24  
Index: detection-rules-ut-236

### Interactive Terminal Spawned via Python

Branch count: 24  
Document count: 24  
Index: detection-rules-ut-237

### KRBTGT Delegation Backdoor

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-612

### Kerberos Cached Credentials Dumping

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-259

### Kerberos Traffic from Unusual Process

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-419

### Kernel Module Removal

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-232

### Keychain Password Retrieval via Command Line

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-260

### LSASS Memory Dump Creation

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-420

### LSASS Memory Dump Handle Access

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-421

### Lateral Movement via Startup Folder

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-597

### Lateral Tool Transfer

Branch count: 8  
Document count: 16  
Index: detection-rules-ut-583

### Launch Agent Creation or Modification and Immediate Loading

Branch count: 8  
Document count: 16  
Index: detection-rules-ut-289

### Linux Restricted Shell Breakout via  apt/apt-get Changelog Escape

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-220

### Linux Restricted Shell Breakout via awk Commands

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-223

### Linux Restricted Shell Breakout via env Shell Evasion

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-227

### Linux Restricted Shell Breakout via the find command

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-230

### Local Scheduled Task Creation

Branch count: 24  
Document count: 48  
Index: detection-rules-ut-608

### MFA Disabled for Google Workspace Organization

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-154

### Malware - Detected - Elastic Endgame

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-383

### Malware - Prevented - Elastic Endgame

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-384

### Microsoft 365 Exchange Anti-Phish Policy Deletion

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-173

### Microsoft 365 Exchange Anti-Phish Rule Modification

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-174

### Microsoft 365 Exchange DKIM Signing Configuration Disabled

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-181

### Microsoft 365 Exchange DLP Policy Removed

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-163

### Microsoft 365 Exchange Malware Filter Policy Deletion

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-164

### Microsoft 365 Exchange Malware Filter Rule Modification

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-165

### Microsoft 365 Exchange Management Group Role Assignment

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-184

### Microsoft 365 Exchange Safe Attachment Rule Disabled

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-166

### Microsoft 365 Exchange Safe Link Policy Disabled

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-175

### Microsoft 365 Exchange Transport Rule Creation

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-168

### Microsoft 365 Exchange Transport Rule Modification

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-169

### Microsoft 365 Global Administrator Role Assigned

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-185

### Microsoft 365 Impossible travel activity

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-176

### Microsoft 365 Inbox Forwarding Rule Created

Branch count: 12  
Document count: 12  
Index: detection-rules-ut-159

### Microsoft 365 Mass download by a single user

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-170

### Microsoft 365 Potential ransomware activity

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-171

### Microsoft 365 Teams Custom Application Interaction Allowed

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-182

### Microsoft 365 Teams External Access Enabled

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-186

### Microsoft 365 Teams Guest Access Enabled

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-187

### Microsoft 365 Unusual Volume of File Deletion

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-172

### Microsoft 365 User Restricted from Sending Email

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-177

### Microsoft Build Engine Loading Windows Credential Libraries

Branch count: 8  
Document count: 16  
Index: detection-rules-ut-412

### Microsoft Build Engine Started an Unusual Process

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-464

### Microsoft Build Engine Started by a Script Process

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-461

### Microsoft Build Engine Started by a System Process

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-462

### Microsoft Build Engine Started by an Office Application

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-460

### Microsoft Build Engine Using an Alternate Name

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-463

### Microsoft Exchange Server UM Spawning Suspicious Processes

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-568

### Microsoft Exchange Server UM Writing Suspicious Files

Branch count: 12  
Document count: 12  
Index: detection-rules-ut-567

### Microsoft Exchange Worker Spawning Suspicious Processes

Branch count: 20  
Document count: 20  
Index: detection-rules-ut-569

### Microsoft IIS Connection Strings Decryption

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-418

### Microsoft IIS Service Account Password Dumped

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-417

### Mimikatz Memssp Log File Detected

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-422

### Mimikatz Powershell Module Activity

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-423

### Modification of Boot Configuration

Branch count: 20  
Document count: 20  
Index: detection-rules-ut-560

### Modification of Dynamic Linker Preload Shared Object

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-253

### Modification of Environment Variable via Launchctl

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-269

### Modification of OpenSSH Binaries

Branch count: 20  
Document count: 20  
Index: detection-rules-ut-250

### Modification of Safari Settings via Defaults Command

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-272

### Modification of Standard Authentication Module or Configuration

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-018

### Modification or Removal of an Okta Application Sign-On Policy

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-210

### Mounting Hidden or WebDav Remote Shares

Branch count: 32  
Document count: 32  
Index: detection-rules-ut-588

### MsBuild Making Network Connections

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-481

### MsBuild Network Connection Sequence

Branch count: 16  
Document count: 32  
Index: detection-rules-ut-480

### MsXsl Making Network Connections

Branch count: 8  
Document count: 16  
Index: detection-rules-ut-483

### Mshta Making Network Connections

Branch count: 8  
Document count: 16  
Index: detection-rules-ut-482

### Multi-Factor Authentication Disabled for an Azure User

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-118

### NTDS or SAM Database File Copied

Branch count: 32  
Document count: 32  
Index: detection-rules-ut-411

### Net command via SYSTEM account

Branch count: 20  
Document count: 20  
Index: detection-rules-ut-519

### Netcat Network Activity

Branch count: 100  
Document count: 200  
Index: detection-rules-ut-246

### Network Connection via Certutil

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-397

### Network Connection via Compiled HTML File

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-540

### Network Connection via MsXsl

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-484

### Network Connection via Registration Utility

Branch count: 8  
Document count: 16  
Index: detection-rules-ut-546

### Network Connection via Signed Binary

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-478

### New ActiveSyncAllowedDeviceID Added via PowerShell

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-613

### New or Modified Federation Domain

Branch count: 24  
Document count: 24  
Index: detection-rules-ut-188

### Nping Process Activity

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-247

### O365 Email Reported by User as Malware or Phish

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-178

### O365 Exchange Suspicious Mailbox Right Delegation

Branch count: 12  
Document count: 12  
Index: detection-rules-ut-183

### O365 Mailbox Audit Logging Bypass

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-167

### OneDrive Malware File Upload

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-179

### Outbound Scheduled Task Activity via PowerShell

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-547

### Parent Process PID Spoofing

Branch count: 24  
Document count: 48  
Index: detection-rules-ut-486

### Peripheral Device Discovery

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-521

### Permission Theft - Detected - Elastic Endgame

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-385

### Permission Theft - Prevented - Elastic Endgame

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-386

### Persistence via BITS Job Notify Cmdline

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-633

### Persistence via Hidden Run Key Detected

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-634

### Persistence via KDE AutoStart Script or Desktop File Modification

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-251

### Persistence via Microsoft Office AddIns

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-610

### Persistence via Microsoft Outlook VBA

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-611

### Persistence via Scheduled Job Creation

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-607

### Persistence via TelemetryController Scheduled Task Hijack

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-636

### Persistence via Update Orchestrator Service Hijack

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-637

### Persistence via WMI Event Subscription

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-638

### Persistent Scripts in the Startup Directory

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-622

### Port Forwarding Rule Addition

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-402

### Possible Consent Grant Attack via Azure-Registered Application

Branch count: 72  
Document count: 72  
Index: detection-rules-ut-109

### Possible Okta DoS Attack

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-197

### Potential Abuse of Repeated MFA Push Notifications

Branch count: 4  
Document count: 12  
Index: detection-rules-ut-193

### Potential Application Shimming via Sdbinst

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-632

### Potential Command and Control via Internet Explorer

Branch count: 4  
Document count: 12  
Index: detection-rules-ut-401

### Potential Cookies Theft via Browser Debugging

Branch count: 84  
Document count: 84  
Index: detection-rules-ut-004

### Potential Credential Access via DCSync

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-413

### Potential Credential Access via DuplicateHandle in LSASS

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-429

### Potential Credential Access via LSASS Memory Dump

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-435

### Potential Credential Access via Renamed COM+ Services DLL

Branch count: 8  
Document count: 16  
Index: detection-rules-ut-434

### Potential DLL Side-Loading via Microsoft Antimalware Service Executable

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-466

### Potential DLL SideLoading via Trusted Microsoft Programs

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-465

### Potential DNS Tunneling via Iodine

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-245

### Potential Disabling of SELinux

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-226

### Potential Evasion via Filter Manager

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-513

### Potential JAVA/JNDI Exploitation Attempt

Branch count: 20  
Document count: 40  
Index: detection-rules-ut-015

### Potential Kerberos Attack via Bifrost

Branch count: 24  
Document count: 24  
Index: detection-rules-ut-284

### Potential LSA Authentication Package Abuse

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-646

### Potential LSASS Clone Creation via PssCaptureSnapShot

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-438

### Potential Microsoft Office Sandbox Evasion

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-273

### Potential Modification of Accessibility Binaries

Branch count: 12  
Document count: 12  
Index: detection-rules-ut-614

### Potential OpenSSH Backdoor Logging Activity

Branch count: 12  
Document count: 12  
Index: detection-rules-ut-219

### Potential Persistence via Login Hook

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-303

### Potential Persistence via Periodic Tasks

Branch count: 12  
Document count: 12  
Index: detection-rules-ut-305

### Potential PrintNightmare File Modification

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-650

### Potential Privacy Control Bypass via TCCDB Modification

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-270

### Potential Privilege Escalation via InstallerFileTakeOver

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-645

### Potential Privilege Escalation via PKEXEC

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-254

### Potential Privilege Escalation via Sudoers File Modification

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-021

### Potential Privileged Escalation via SamAccountName Spoofing

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-657

### Potential Process Herpaderping Attempt

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-490

### Potential Protocol Tunneling via EarthWorm

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-217

### Potential Remote Desktop Shadowing Activity

Branch count: 12  
Document count: 12  
Index: detection-rules-ut-582

### Potential Remote Desktop Tunneling Detected

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-403

### Potential Reverse Shell Activity via Terminal

Branch count: 40  
Document count: 40  
Index: detection-rules-ut-013

### Potential Secure File Deletion via SDelete Utility

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-495

### Potential Shadow Credentials added to AD Object

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-433

### Potential Shell via Web Server

Branch count: 64  
Document count: 64  
Index: detection-rules-ut-252

### Potential Windows Error Manager Masquerading

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-476

### PowerShell Kerberos Ticket Request

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-428

### PowerShell Keylogging Script

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-394

### PowerShell MiniDump Script

Branch count: 12  
Document count: 12  
Index: detection-rules-ut-427

### PowerShell PSReflect Script

Branch count: 36  
Document count: 36  
Index: detection-rules-ut-544

### PowerShell Suspicious Discovery Related Windows API Functions

Branch count: 44  
Document count: 44  
Index: detection-rules-ut-522

### Privilege Escalation via Named Pipe Impersonation

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-647

### Privilege Escalation via Rogue Named Pipe Impersonation

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-670

### Privilege Escalation via Root Crontab File Modification

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-314

### Process Activity via Compiled HTML File

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-555

### Process Execution from an Unusual Directory

Branch count: 12  
Document count: 12  
Index: detection-rules-ut-538

### Process Injection - Detected - Elastic Endgame

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-387

### Process Injection - Prevented - Elastic Endgame

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-388

### Process Injection by the Microsoft Build Engine

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-470

### Process Termination followed by Deletion

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-492

### Program Files Directory Masquerading

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-475

### PsExec Network Connection

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-545

### Python Script Execution via Command Line

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-012

### RDP (Remote Desktop Protocol) from the Internet

Branch count: 48  
Document count: 48  
Index: detection-rules-ut-368

### RPC (Remote Procedure Call) from the Internet

Branch count: 48  
Document count: 48  
Index: detection-rules-ut-372

### RPC (Remote Procedure Call) to the Internet

Branch count: 48  
Document count: 48  
Index: detection-rules-ut-373

### Ransomware - Detected - Elastic Endgame

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-389

### Ransomware - Prevented - Elastic Endgame

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-390

### Registry Hive File Creation via SMB

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-425

### Registry Persistence via AppCert DLL

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-601

### Registry Persistence via AppInit DLL

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-602

### Remote Desktop Enabled in Windows Firewall

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-456

### Remote Execution via File Shares

Branch count: 16  
Document count: 32  
Index: detection-rules-ut-585

### Remote File Copy to a Hidden Share

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-592

### Remote File Copy via TeamViewer

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-409

### Remote File Download via Desktopimgdownldr Utility

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-404

### Remote File Download via MpCmdRun

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-405

### Remote File Download via PowerShell

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-406

### Remote File Download via Script Interpreter

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-407

### Remote SSH Login Enabled via systemsetup Command

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-286

### Remote Scheduled Task Creation

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-594

### Remote System Discovery Commands

Branch count: 12  
Document count: 12  
Index: detection-rules-ut-525

### Remotely Started Services via RPC

Branch count: 32  
Document count: 64  
Index: detection-rules-ut-593

### Renamed AutoIt Scripts Interpreter

Branch count: 12  
Document count: 12  
Index: detection-rules-ut-473

### SMB (Windows File Sharing) Activity to the Internet

Branch count: 72  
Document count: 72  
Index: detection-rules-ut-374

### SMTP on Port 26/TCP

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-367

### SSH Authorized Keys File Modification

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-020

### Scheduled Task Created by a Windows Script

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-609

### Screensaver Plist File Modified by Unexpected Process

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-307

### Searching for Saved Credentials via VaultCmd

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-431

### Security Software Discovery using WMIC

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-526

### Security Software Discovery via Grep

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-009

### Sensitive Privilege SeEnableDelegationPrivilege assigned to a User

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-432

### Service Command Lateral Movement

Branch count: 16  
Document count: 32  
Index: detection-rules-ut-575

### Service Control Spawned via Script Interpreter

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-595

### SharePoint Malware File Upload

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-180

### Shell Execution via Apple Scripting

Branch count: 24  
Document count: 48  
Index: detection-rules-ut-282

### Shortcut File Written or Modified for Persistence

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-620

### Signed Proxy Execution via MS WorkFolders

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-515

### Startup Folder Persistence via Unsigned Process

Branch count: 8  
Document count: 16  
Index: detection-rules-ut-621

### Strace Process Activity

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-249

### Sublime Plugin or Application Script Modification

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-304

### Sudoers File Modification

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-024

### Suspicious .NET Code Compilation

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-455

### Suspicious .NET Reflection via PowerShell

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-487

### Suspicious Activity Reported by Okta User

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-199

### Suspicious Automator Workflows Execution

Branch count: 8  
Document count: 16  
Index: detection-rules-ut-280

### Suspicious CertUtil Commands

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-498

### Suspicious Child Process of Adobe Acrobat Reader Update Service

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-312

### Suspicious Cmd Execution via WMI

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-549

### Suspicious DLL Loaded for Persistence or Privilege Escalation

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-648

### Suspicious Emond Child Process

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-297

### Suspicious Endpoint Security Parent Process

Branch count: 12  
Document count: 12  
Index: detection-rules-ut-472

### Suspicious Execution from a Mounted Device

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-499

### Suspicious Execution via Scheduled Task

Branch count: 64  
Document count: 64  
Index: detection-rules-ut-625

### Suspicious Explorer Child Process

Branch count: 64  
Document count: 64  
Index: detection-rules-ut-574

### Suspicious Hidden Child Process of Launchd

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-293

### Suspicious Image Load (taskschd.dll) from MS Office

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-624

### Suspicious JAVA Child Process

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-014

### Suspicious MS Office Child Process

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-570

### Suspicious MS Outlook Child Process

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-571

### Suspicious Managed Code Hosting Process

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-500

### Suspicious PDF Reader Child Process

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-551

### Suspicious Portable Executable Encoded in Powershell Script

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-543

### Suspicious Print Spooler File Deletion

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-654

### Suspicious PrintSpooler SPL File Created

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-655

### Suspicious PrintSpooler Service Executable File Creation

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-653

### Suspicious Process Creation CallTrace

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-502

### Suspicious Process Execution via Renamed PsExec Executable

Branch count: 12  
Document count: 12  
Index: detection-rules-ut-553

### Suspicious Process from Conhost

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-444

### Suspicious RDP ActiveX Client Loaded

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-596

### Suspicious Script Object Execution

Branch count: 8  
Document count: 16  
Index: detection-rules-ut-503

### Suspicious SolarWinds Child Process

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-529

### Suspicious WMI Image Load from MS Office

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-550

### Suspicious WerFault Child Process

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-474

### Suspicious Zoom Child Process

Branch count: 12  
Document count: 12  
Index: detection-rules-ut-505

### Suspicious macOS MS Office Child Process

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-283

### Svchost spawning Cmd

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-532

### Symbolic Link to Shadow Copy Created

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-437

### System Log File Deletion

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-233

### System Shells via Services

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-627

### SystemKey Access via Command Line

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-264

### TCC Bypass via Mounted APFS Snapshot Access

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-274

### Tampering of Bash Command-Line History

Branch count: 40  
Document count: 40  
Index: detection-rules-ut-225

### Telnet Port Activity

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-369

### Third-party Backup Files Deleted via Unexpected Process

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-558

### Threat Detected by Okta ThreatInsight

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-211

### Timestomping using Touch Command

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-008

### UAC Bypass Attempt via Elevated COM Internet Explorer Add-On Installer

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-659

### UAC Bypass Attempt via Privileged IFileOperation COM Interface

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-662

### UAC Bypass Attempt via Windows Directory Masquerading

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-664

### UAC Bypass Attempt with IEditionUpgradeManager Elevated COM Interface

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-658

### UAC Bypass via DiskCleanup Scheduled Task Hijack

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-661

### UAC Bypass via ICMLuaUtil Elevated COM Interface

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-660

### UAC Bypass via Windows Firewall Snap-In Hijack

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-665

### Unauthorized Access to an Okta Application

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-198

### Unexpected Child Process of macOS Screensaver Engine

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-306

### Unusual Child Process from a System Virtual Process

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-512

### Unusual Child Process of dns.exe

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-572

### Unusual Child Processes of RunDLL32

Branch count: 32  
Document count: 64  
Index: detection-rules-ut-493

### Unusual Executable File Creation by a System Critical Process

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-506

### Unusual File Creation - Alternate Data Stream

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-507

### Unusual File Modification by dns.exe

Branch count: 12  
Document count: 12  
Index: detection-rules-ut-573

### Unusual Network Activity from a Windows System Binary

Branch count: 8  
Document count: 16  
Index: detection-rules-ut-485

### Unusual Network Connection via DllHost

Branch count: 8  
Document count: 16  
Index: detection-rules-ut-509

### Unusual Network Connection via RunDLL32

Branch count: 8  
Document count: 16  
Index: detection-rules-ut-510

### Unusual Parent Process for cmd.exe

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-533

### Unusual Process Execution - Temp

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-248

### Unusual Process Execution Path - Alternate Data Stream

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-508

### Unusual Process Network Connection

Branch count: 4  
Document count: 8  
Index: detection-rules-ut-511

### Unusual Service Host Child Process - Childless Service

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-669

### User Account Creation

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-630

### User Added as Owner for Azure Application

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-119

### User Added as Owner for Azure Service Principal

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-120

### User Added to Privileged Group in Active Directory

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-629

### VNC (Virtual Network Computing) from the Internet

Branch count: 24  
Document count: 24  
Index: detection-rules-ut-370

### VNC (Virtual Network Computing) to the Internet

Branch count: 24  
Document count: 24  
Index: detection-rules-ut-371

### Virtual Machine Fingerprinting

Branch count: 40  
Document count: 40  
Index: detection-rules-ut-235

### Virtual Machine Fingerprinting via Grep

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-010

### Volume Shadow Copy Deleted or Resized via VssAdmin

Branch count: 32  
Document count: 32  
Index: detection-rules-ut-562

### Volume Shadow Copy Deletion via PowerShell

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-563

### Volume Shadow Copy Deletion via WMIC

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-564

### WMI Incoming Lateral Movement

Branch count: 8  
Document count: 16  
Index: detection-rules-ut-587

### WPAD Service Exploit

Branch count: 16  
Document count: 80  
Index: detection-rules-ut-672

### Web Application Suspicious Activity: POST Request Declined

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-000

### Web Application Suspicious Activity: Unauthorized Method

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-001

### Web Application Suspicious Activity: sqlmap User Agent

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-003

### WebProxy Settings Modification

Branch count: 12  
Document count: 12  
Index: detection-rules-ut-261

### WebServer Access Logs Deleted

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-007

### Webshell Detection: Script Process Child of Common Web Processes

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-640

### Whoami Process Activity

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-527

### Windows Defender Exclusions Added via PowerShell

Branch count: 16  
Document count: 16  
Index: detection-rules-ut-448

### Windows Event Logs Cleared

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-443

### Windows Firewall Disabled via PowerShell

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-491

### Windows Network Enumeration

Branch count: 64  
Document count: 64  
Index: detection-rules-ut-520

### Windows Script Executing PowerShell

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-565

### Windows Script Interpreter Executing Process via WMI

Branch count: 16  
Document count: 32  
Index: detection-rules-ut-566

### Windows Service Installed via an Unusual Client

Branch count: 8  
Document count: 8  
Index: detection-rules-ut-671

### Zoom Meeting with no Passcode

Branch count: 4  
Document count: 4  
Index: detection-rules-ut-017

### macOS Installer Spawns Network Event

Branch count: 8  
Document count: 16  
Index: detection-rules-ut-279

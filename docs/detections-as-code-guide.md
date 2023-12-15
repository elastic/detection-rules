## Detections-as-Code Guide
Description: This repository supports the use of Detections-as-Code (DaC) as a user. This is done via various functionality and features that are available.

Table-of-Contents:

Pre-requisite Information: (DEFINITELY - blog and reference)
- Basic understanding of schemas
- Basic understanding of rule loading
- Basic understanding of query validation
- Basic understanding of rule validation
- Basic understanding of custom unit tests vs upstream requirements

### Rule Lifecycle Management
#### Rule Validation
- Rule data validation (local & remote)
- Rule query validation (local & remote)
  - Do we require this since schemas are potentially diverged
#### Custom vs Prebuilt
- Differentiate between custom and prebuilt
- Rule location
- File naming
- Rule loading
#### Create Custom Rules
- `create-rule` command (non-interactive)
#### Read Custom Rules
#### Update Custom Rules
#### Delete Custom Rules
#### Exporting Custom Rules
- Kibana to NDJSON File (UI)
- Kibana API Endpoint to NDJSON File
- Kibana API Endpoint to TOML File
#### Uploading Custom Rules
- TOML to NDJSON File
- TOML to JSON (Memory) to Kibana API Endpoint
#### Version Control
- TRaDE - What options are available upstream?
- CLI based version bumping
- Extension of SHA256 version control
#### Kibana API Endpoints
- Detection Engine endpoint API
- Create rule, delete rule, rule metrics, etc.
- Rather than CLI, import helper methods to send requests to endpoint API
#### Rule Exploration
- Search and download alerts/events by rule
- Search installed rules
- Search disabled vs enabled rules
- Preview rule Kibana endpoint API
#### Unit Tests
- Required unit tests
- TRaDE specific unit tests
- Configuration to skip non-required unit tests


Useful Commands:
`validate-rule`: Loads a specified TOML rule and does rule/query validation
`validate-all`: Similar to `validate-rule` but validates for all rules
`view-rule`: Similar to `validate-rule` but returns Kibana API formatted JSON object
`export-rules`: Loads rules from TOML files and dumps to NDJSON file where rules are Kibana API formatted
`import-rules`: Loads rules from JSON (or NDJSON) files, loads through schemas and stores in TOML
`create-rule`: Offers interactive rule generation which loads data through schemas and drops TOML file

Kibana Library


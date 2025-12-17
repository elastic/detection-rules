#!/bin/bash

# Path to the virtual environment
VENV_PATH="./env/detection-rules-build"

# Activate the virtual environment
source "$VENV_PATH/bin/activate"

echo "Running detection-rules CLI tests..."

echo "Refreshing redirect mappings in ATT&CK"
python -m detection_rules dev attack refresh-redirect-mappings

echo "Viewing rule: threat_intel_indicator_match_address.toml"
python -m detection_rules view-rule rules/threat_intel/threat_intel_indicator_match_address.toml

echo "Exporting rule by ID: 0a97b20f-4144-49ea-be32-b540ecc445de"
mkdir tmp-export 2>/dev/null
python -m detection_rules export-rules-from-repo --rule-id 0a97b20f-4144-49ea-be32-b540ecc445de -o tmp-export/test_rule.ndjson

echo "Importing rule by ID: 0a97b20f-4144-49ea-be32-b540ecc445de"
python -m detection_rules import-rules-to-repo tmp-export/test_rule.ndjson --required-only -s tmp-export
rm -rf tmp-export

echo "Updating rule data schemas"
python -m detection_rules dev schemas update-rule-data

echo "Generate Beats schemas"
GITHUB_TOKEN="foo" python -m detection_rules dev schemas generate --schema beats

echo "Validating rule: execution_github_new_event_action_for_pat.toml"
python -m detection_rules validate-rule rules_building_block/execution_github_new_event_action_for_pat.toml

echo "Linting Rule: command_and_control_common_webservices.toml"
python -m detection_rules toml-lint -f rules/windows/command_and_control_common_webservices.toml

echo "Checking licenses"
python -m detection_rules dev license-check

echo "Building release and updating version lock"
python -m detection_rules dev build-release --update-version-lock

echo "Refreshing ATT&CK data"
python -m detection_rules dev attack refresh-data

echo "Updating rules with latest ATT&CK data"
python -m detection_rules dev attack update-rules

echo "Getting target branches"
python -m detection_rules dev utils get-branches

echo "Showing latest compatible version for security_detection_engine with stack version 8.12.0"
python -m detection_rules dev integrations show-latest-compatible --package endpoint --stack_version 8.12.0

echo "Building limited rules for stack version 8.12"
python -m detection_rules build-limited-rules --stack-version "8.12" --output-file "output_file.ndjson"

echo "Building limited rules for stack version 8.12 with custom rules"
python -m detection_rules generate-rules-index --overwrite

echo "Building manifests for integrations"
python -m detection_rules dev integrations build-manifests -i endpoint

echo "Building schemas for integrations"
python -m detection_rules dev integrations build-schemas -i endpoint

echo "Detection-rules CLI tests completed!"

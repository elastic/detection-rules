#!/bin/bash

# Path to the virtual environment
VENV_PATH="./env/detection-rules-build"

# Activate the virtual environment
source "$VENV_PATH/bin/activate"

echo "Running detection-rules remote CLI tests..."

echo "Performing a quick rule alerts search..."
echo "Requires .detection-rules-cfg.json credentials file set."
python -m detection_rules kibana search-alerts

echo "Setting Up Custom Directory..."
mkdir tmp-custom 2>/dev/null
python -m detection_rules custom-rules setup-config tmp-custom
export CUSTOM_RULES_DIR=./tmp-custom/

echo "Performing a rule conversion from ndjson to toml files..."
python -m detection_rules import-rules-to-repo detection_rules/etc/custom-consolidated-rules.ndjson -ac -e -s $CUSTOM_RULES_DIR/rules --required-only

echo "Performing a rule import to kibana..."

python -m detection_rules kibana import-rules -o -e -ac

echo "Performing a rule export..."
python -m detection_rules kibana export-rules -d $CUSTOM_RULES_DIR -ac -e -sv --custom-rules-only 

echo "Testing ESQL Rules..."
python -m pytest tests/test_rules_remote.py::TestRemoteRules

echo "Removing generated files..."
rm -rf $CUSTOM_RULES_DIR
set -e CUSTOM_RULES_DIR

echo "Detection-rules Remote CLI tests completed!"

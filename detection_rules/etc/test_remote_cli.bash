#!/bin/bash

# Path to the virtual environment
VENV_PATH="./env/detection-rules-build"

# Activate the virtual environment
source "$VENV_PATH/bin/activate"

echo "Running detection-rules remote CLI tests..."

echo "Performing a quick rule alerts search..."
echo "Requires .detection-rules-cfg.json credentials file set."
python -m detection_rules kibana search-alerts

echo "Performing a rule export..."
mkdir tmp-export 2>/dev/null
python -m detection_rules kibana export-rules -d tmp-export -sv --skip-errors -r 565d6ca5-75ba-4c82-9b13-add25353471c
ls tmp-export
echo "Removing generated files..."
rm -rf tmp-export

echo "Performing a rule import..."

python -m detection_rules custom-rules setup-config tmp-custom
export CUSTOM_RULES_DIR=./tmp-custom
cp rules/threat_intel/threat_intel_indicator_match_address.toml tmp-custom/rules/
python -m detection_rules kibana import-rules -o -e -ac
rm -rf tmp-custom
set -e CUSTOM_RULES_DIR

echo "Detection-rules Remote CLI tests completed!"

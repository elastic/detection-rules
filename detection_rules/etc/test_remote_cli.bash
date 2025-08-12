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

echo "Performing a rule export..."
python -m detection_rules kibana export-rules -d $CUSTOM_RULES_DIR -sv --skip-errors -r 565d6ca5-75ba-4c82-9b13-add25353471c #eql-rule
python -m detection_rules kibana export-rules -d $CUSTOM_RULES_DIR -sv --skip-errors -r e6c1a552-7776-44ad-ae0f-8746cc07773c #kql-rule
python -m detection_rules kibana export-rules -d $CUSTOM_RULES_DIR -sv --skip-errors -r e903ce9a-5ce6-4246-bb14-75ed3ec2edf5 #esql-rule
python -m detection_rules kibana export-rules -d $CUSTOM_RULES_DIR -sv --skip-errors -r a61809f3-fb5b-465c-8bff-23a8a068ac60 #indicator-match-rule
python -m detection_rules kibana export-rules -d $CUSTOM_RULES_DIR -sv --skip-errors -r 035889c4-2686-4583-a7df-67f89c292f2c #threshold-rule
python -m detection_rules kibana export-rules -d $CUSTOM_RULES_DIR -sv --skip-errors -r 6b84d470-9036-4cc0-a27c-6d90bbfe81ab #new_terms-rule
python -m detection_rules kibana export-rules -d $CUSTOM_RULES_DIR -sv --skip-errors -r 9d302377-d226-4e12-b54c-1906b5aec4f6 #machine-learning-rule

# Reorder the rules to ensure they are in the correct directory
echo "Moving exported rules to the rules directory..."
mv $CUSTOM_RULES_DIR/*.toml $CUSTOM_RULES_DIR/rules/.

echo "Performing a rule import..."

python -m detection_rules kibana import-rules -o -e -ac
echo "Removing generated files..."
rm -rf $CUSTOM_RULES_DIR
set -e CUSTOM_RULES_DIR

echo "Detection-rules Remote CLI tests completed!"

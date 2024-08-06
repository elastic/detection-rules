#!/bin/bash

# Path to the virtual environment
VENV_PATH="./env/detection-rules-build"

# Activate the virtual environment
source "$VENV_PATH/bin/activate"

echo "Running detection-rules remote CLI tests for custom rules..."

echo "Performing a quick rule alerts search..."
echo "Requires .detection-rules-cfg.json credentials file set."
python -m detection_rules kibana search-alerts

echo "Performing a rule import..."
python -m detection_rules kibana import-rules --overwrite -e -ac

echo "Running Tests..."
make test

echo "Performing a rule export..."
mkdir tmp-export 2>/dev/null
python -m detection_rules kibana export-rules -d tmp-export -s -sv -e -ac


echo "Detection-rules CLI tests completed!"
#
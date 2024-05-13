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
python -m detection_rules kibana export-rules-from-repo -d tmp-export --skip-errors
ls tmp-export
echo "Removing generated files..."
rm -rf tmp-export

echo "Detection-rules CLI tests completed!"

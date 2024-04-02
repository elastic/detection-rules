#!/bin/bash

# Path to the virtual environment
VENV_PATH="./env/detection-rules-build"

# Activate the virtual environment
source "$VENV_PATH/bin/activate"

echo "Running detection-rules remote CLI tests..."

echo "Performing a quick rule alerts search..."
echo "Requires .detection-rules-cfg.json credentials file set."
python -m detection_rules kibana search-alerts

echo "Detection-rules CLI tests completed!"

#!/bin/bash

# Path to the virtual environment
VENV_PATH="./env/detection-rules-build"

# Activate the virtual environment
source "$VENV_PATH/bin/activate"

# Get the ndjson file path from the first argument
ndjson_file_path=$1

echo "Running detection-rules CLI tests for custom rules..."

echo "Importing rules from specified njson..."
python -m detection_rules import-rules-to-repo $ndjson_file_path --required-only -e -ac

echo "Run tests..."
make test

echo "Performing a rule export to nsjdon..."
python -m detection_rules export-rules-from-repo -e -ac

echo "Detection-rules CLI tests completed!"

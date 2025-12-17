#!/bin/bash

# Path to the virtual environment
VENV_PATH="./env/detection-rules-build"

# Activate the virtual environment
source "$VENV_PATH/bin/activate"

echo "Running hunting CLI tests..."

echo "Searching: Search for T1078.004 subtechnique in AWS data source"
python -m hunting search --sub-technique T1078.004 --data-source aws

echo "Refreshing index"
python -m hunting refresh-index

echo "Generating Markdown: initial_access_higher_than_average_failed_authentication.toml"
python -m hunting generate-markdown hunting/okta/queries/initial_access_higher_than_average_failed_authentication.toml

echo "Running Query: low_volume_external_network_connections_from_process.toml"
echo "Requires .detection-rules-cfg.json credentials file set."
python -m hunting run-query --file-path hunting/linux/queries/low_volume_external_network_connections_from_process.toml --all

echo "Viewing Hunt: 12526f14-5e35-4f5f-884c-96c6a353a544"
python -m hunting view-hunt --uuid 12526f14-5e35-4f5f-884c-96c6a353a544 --format json

echo "Generating summary of hunts by integration"
python -m hunting hunt-summary --breakdown integration

echo "Generating summary of hunts by platform"
python -m hunting hunt-summary --breakdown platform

echo "Generating summary of hunts by language"
python -m hunting hunt-summary --breakdown language

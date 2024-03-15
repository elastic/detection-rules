#################
### detection-rules
#################

VENV := ./env/detection-rules-build
VENV_BIN := $(VENV)/bin
PYTHON := $(VENV_BIN)/python
PIP := $(VENV_BIN)/pip


.PHONY: all
all: release

$(VENV):
	python3.12 -m pip install --upgrade pip setuptools
	python3.12 -m venv $(VENV)

.PHONY: clean
clean:
	rm -rf $(VENV) *.egg-info .eggs .egg htmlcov build dist packages .build .tmp .tox __pycache__  lib/kql/build lib/kibana/build lib/kql/*.egg-info lib/kibana/*.egg-info

.PHONY: deps
deps: $(VENV) install-packages
	@echo "Installing all dependencies..."
	$(PIP) install .[dev]

.PHONY: install-packages
install-packages:
	@echo "Installing kql and kibana packages..."
	$(PIP) install lib/kql lib/kibana

.PHONY: pytest
pytest: $(VENV) deps
	$(PYTHON) -m detection_rules test

.PHONY: license-check
license-check: $(VENV) deps
	@echo "LICENSE CHECK"
	$(PYTHON) -m detection_rules dev license-check

.PHONY: lint
lint: $(VENV) deps
	@echo "LINTING"
	$(PYTHON) -m flake8 tests detection_rules --ignore D203 --max-line-length 120

.PHONY: test
test: $(VENV) lint pytest

.PHONY: test-cli
test-cli:
	@echo "Running detection-rules CLI tests..."
	@echo "Refreshing redirect mappings in ATT&CK"
	@$(PYTHON) -m detection_rules dev attack refresh-redirect-mappings
	@echo "Viewing rule: threat_intel_indicator_match_address.toml"
	@$(PYTHON) -m detection_rules view-rule rules/cross-platform/threat_intel_indicator_match_address.toml
	@echo "Exporting rule by ID: 8f6eb3b6-e9f2-4c10-a72b-cf48b4e90c2d"
	@$(PYTHON) -m detection_rules export-rules --rule-id 8f6eb3b6-e9f2-4c10-a72b-cf48b4e90c2d
	@echo "Updating rule data schemas"
	@$(PYTHON) -m detection_rules dev schemas update-rule-data
	@echo "Validating rule: execution_github_new_event_action_for_pat.toml"
	@$(PYTHON) -m detection_rules validate-rule rules_building_block/execution_github_new_event_action_for_pat.toml
	@echo "Checking licenses"
	@$(PYTHON) -m detection_rules dev license-check
	@echo "Building release and updating version lock"
	@$(PYTHON) -m detection_rules dev build-release --update-version-lock
	@echo "Refreshing ATT&CK data"
	@$(PYTHON) -m detection_rules dev attack refresh-data
	@echo "Updating rules with latest ATT&CK data"
	@$(PYTHON) -m detection_rules dev attack update-rules
	@echo "Getting target branches"
	@$(PYTHON) -m detection_rules dev utils get-branches
	@echo "Showing latest compatible version for security_detection_engine with stack version 8.12.0"
	@$(PYTHON) -m detection_rules dev integrations show-latest-compatible --package endpoint --stack_version 8.12.0
	@echo "Building limited rules for stack version 8.12"
	@$(PYTHON) -m detection_rules build-limited-rules --stack-version "8.12" --output-file "output_file.ndjson"
	@echo "Building limited rules for stack version 8.12 with custom rules"
	@$(PYTHON) -m detection_rules generate-rules-index
	@echo "Building manifests for integrations"
	@$(PYTHON) -m detection_rules dev integrations build-manifests -i endpoint
	@echo "Building schemas for integrations"
	@$(PYTHON) -m detection_rules dev integrations build-schemas -i endpoint
	@echo "Detection-rules CLI tests completed!"



.PHONY: release
release: deps
	@echo "RELEASE: $(app_name)"
	$(PYTHON) -m detection_rules dev build-release --generate-navigator
	rm -rf dist
	mkdir dist
	cp -r releases/*/*.zip dist/

.PHONY: kibana-commit
kibana-commit: deps
	@echo "PREP KIBANA-COMMIT: $(app_name)"
	$(PYTHON) -m detection_rules dev kibana-commit

#################
### detection-rules
#################

APP_NAME := detection-rules
VENV := ./env/detection-rules-build
VENV_BIN := $(VENV)/bin
PYTHON := $(VENV_BIN)/python
PIP := $(VENV_BIN)/pip


.PHONY: all
all: release

$(VENV):
	python3.12 -m venv $(VENV)

.PHONY: clean
clean:
	rm -rf $(VENV) *.egg-info .eggs .egg htmlcov build dist packages .build .tmp .tox __pycache__  lib/kql/build lib/kibana/build lib/kql/*.egg-info lib/kibana/*.egg-info

.PHONY: deps
deps: $(VENV)
	@echo "Installing all dependencies..."
	$(PIP) install .[dev]
	$(PIP) install lib/kibana
	$(PIP) install lib/kql

.PHONY: hunting-deps
hunting-deps: $(VENV)
	@echo "Installing all dependencies..."
	$(PIP) install .[hunting]

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
	$(PYTHON) -m ruff check --exit-non-zero-on-fix
	$(PYTHON) -m ruff format --check
	$(PYTHON) -m pyright

.PHONY: test
test: $(VENV) lint pytest

.PHONY: test-cli
test-cli: $(VENV) deps
	@echo "Executing test_cli script..."
	@./detection_rules/etc/test_cli.bash

.PHONY: test-remote-cli
test-remote-cli: $(VENV) deps
	@echo "Executing test_remote_cli script..."
	@./detection_rules/etc/test_remote_cli.bash

.PHONY: test-hunting-cli
test-hunting-cli: $(VENV) hunting-deps
	@echo "Executing test_hunting_cli script..."
	@./detection_rules/etc/test_hunting_cli.bash

.PHONY: release
release: deps
	@echo "RELEASE: $(APP_NAME)"
	$(PYTHON) -m detection_rules dev build-release --generate-navigator
	rm -rf dist
	mkdir dist
	cp -r releases/*/*.zip dist/

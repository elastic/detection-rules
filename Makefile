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
deps: $(VENV)
	@echo "Installing all dependencies..."
	$(PIP) install .[dev]

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
	$(PYTHON) -m flake8 tests detection_rules --ignore D203,N815 --max-line-length 120

.PHONY: test
test: $(VENV) lint pytest

.PHONY: test-cli
test-cli: $(VENV)
	@echo "Executing test_cli script..."
	@./detection_rules/etc/test_cli.bash

.PHONY: test-remote-cli
test-remote-cli: $(VENV)
	@echo "Executing test_remote_cli script..."
	@./detection_rules/etc/test_remote_cli.bash

.PHONY: release
release: deps
	@echo "RELEASE: $(app_name)"
	$(PYTHON) -m detection_rules dev build-release --generate-navigator
	rm -rf dist
	mkdir dist
	cp -r releases/*/*.zip dist/

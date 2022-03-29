#################
### detection-rules
#################

VENV := ./env/detection-rules-build
VENV_BIN := $(VENV)/bin
PYTHON := $(VENV_BIN)/python
PIP := $(VENV_BIN)/python -m pip


.PHONY: all
all: release


$(VENV):
	pip install virtualenv
	virtualenv $(VENV) --python=python3.8
	$(PIP) install -r requirements.txt
	$(PIP) install setuptools -U


.PHONY: clean
clean:
	rm -rf $(VENV) *.egg-info .eggs .egg htmlcov build dist packages .build .tmp .tox __pycache__

.PHONY: deps
deps: $(VENV)
	$(PIP) install -r requirements.txt


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

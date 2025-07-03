# Agent Instructions: Kibana helper library

The `lib/kibana` directory contains a small package used by the CLI for interacting with Kibana APIs.

- `kibana/connector.py` defines the `Kibana` client used in `detection_rules/kbwrap.py`.
- `kibana/resources.py` contains dataclasses representing Kibana rule resources (`RuleResource`, `Signal`).
- The package is not published to PyPI; during development it is installed from this directory (`pip install lib/kibana`).

Most CLI commands that talk to Kibana import this package. When modifying the client behavior or API interactions, adjust these files and reinstall the package in your environment.

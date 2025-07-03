# Agent Instructions: KQL parsing library

The `lib/kql` directory provides utilities for parsing and converting Kibana Query Language (KQL).

- Core functionality resides in `kql/*.py` (e.g., `parser.py`, `eql2kql.py`, `kql2eql.py`).
- The package is installed locally via `pip install lib/kql` and used throughout the CLI for query validation and conversion.

If you need to extend query parsing logic or add new converters, explore these modules and reinstall the package after changes.

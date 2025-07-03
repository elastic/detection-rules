# Agent Instructions: Repo Overview and CLI

This repository hosts the Elastic Security detection rules and the supporting command line tooling.

## Repository Structure
- `detection_rules/` – main Python package containing the CLI and rule management libraries.
- `lib/` – Python packages that are installed locally (`kibana` and `kql`).
- `rules/` and `rules_building_block/` – rule definitions in TOML format.
- `hunting/` – threat hunting queries with its own lightweight CLI.
- `tests/` – unit tests for the rule loader and CLI utilities.

## CLI Quickstart
- The CLI entry point is `python -m detection_rules` which runs `detection_rules.__main__:main`.
- Commands are implemented with the [click](https://click.palletsprojects.com/) framework in `detection_rules/main.py` and related modules.
- Run `python -m detection_rules --help` to view the available commands. Each subcommand also accepts `--help`.

## Development Notes
- Install dependencies via `make` or with `pip install .[dev] && pip install lib/kibana lib/kql`.
- Unit tests run with `python -m detection_rules test` or `make test`.
- Style is checked with `pre-commit` hooks configured in `.pre-commit-config.yaml`.

### CLI Usage Guidelines
Focus on building new CLI commands and helpers. Avoid running arbitrary commands
from the repository. Only invoke:

- `python -m flake8 tests detection_rules --ignore D203,N815 --max-line-length 120` to lint new code.
- `bandit -r detection_rules -s B101,B603,B404,B607` for a security scan.
- CLI commands necessary to verify new features, such as running a command you
just implemented.

The CLI environment is already available. Launch `python -m detection_rules --help`
to explore commands.

### Using the Test Environment
The test instance credentials are provided via environment variables:
`KIBANA_URL`, `ELASTIC_URL`, `USERNAME`, `PASSWORD` and `API_KEY`. Export these
as `DR_KIBANA_URL`, `DR_ELASTICSEARCH_URL`, `DR_USER`, `DR_PASSWORD` and
`DR_API_KEY` to allow the CLI to automatically authenticate. Alternatively you
can create a `.detection-rules-cfg.json` (or `.yaml`) file with the same keys, or
pass them directly as command arguments. Do **not** commit the config file or
secrets.

When developing new CLI features, look under `detection_rules/` for the relevant
command group or utility functions. Additional summaries of subfolders are
provided in their respective `AGENTS.md` files.

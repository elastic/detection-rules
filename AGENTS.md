# Agent Instructions: Repo Overview and CLI

This repository hosts the Elastic Security detection rules and the supporting command line tooling.

## Repository Structure
- `detection_rules/` – main Python package containing the CLI and rule management libraries.
- `lib/` – Python packages that are installed locally (`kibana` and `kql`).
- `rules/` and `rules_building_block/` – rule definitions in TOML format.
- `hunting/` – threat hunting queries with its own lightweight CLI.
- `tests/` – unit tests for the rule loader and CLI utilities.

## CLI Quickstart
- Always start with an active environment `source env/detection-rules-build/bin/activate`. The dependencies are already installed via `make deps`.
- The CLI entry point is `python -m detection_rules` which runs `detection_rules.__main__:main`.
- Commands are implemented with the [click](https://click.palletsprojects.com/) framework in `detection_rules/main.py` and related modules.
- Run `python -m detection_rules --help` to view the available commands. Each subcommand also accepts `--help`.
- You can access a test instance to validate implementations like this
```sh
export DR_KIBANA_URL=$KIBANA_URL
export DR_API_KEY=$API_KEY

# test connection to Kibana
python -m detection_rules kibana search-alerts
```
- You can even test it by importing and exporting rules. But to avoid long executions, it is recommended to use a custom rules folder for testing like the `rules-test` folder in this repository. But mind that the elastic instance is reused by many contributors so the state might change at any time. One way to test a rule import would be to use this e.g.:
```sh
# test rule import
export CUSTOM_RULES_DIR=./rules-test
python -m detection_rules import-rules -d $CUSTOM_RULES_DIR/rules \
    --overwrite --overwrite-action-connectors --overwrite-exceptions
```

### Genereal Information
Focus on building new CLI commands and helpers. Avoid running arbitrary commands
from the repository. For linting use ruff, e.g:
- `python -m ruff check --exit-non-zero-on-fix`

Never commit any secrets or sensitive information like environment variables!

When developing new CLI features, look under `detection_rules/` for the relevant
command group or utility functions. Additional summaries of subfolders are
provided in their respective `AGENTS.md` files.

One always active task which should not be neglected is to keep the `AGENTS.md` files up to date. If you encounter issues when using functions or the cli and found a fix on how to use it, please directly document it. Basically for every issue you encounter or where you have to iterate to figure out the correct approach, just document it. The main goal of the AGENTS.md files is to reduce the time it takes to contribute to this repository and reduce the iterations needed to figure out nice workflows or how things work and are structured or how to approach new tasks. So document issues and solutions which you come across your way. This will help you and others to not run into the same issues again and again.
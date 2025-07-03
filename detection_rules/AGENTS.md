# Agent Instructions: detection_rules package

This directory is the main Python package implementing the CLI.  Key files and their roles are listed below.

## Entry Points
- `__main__.py` – prints a banner and invokes the CLI. Executed when running `python -m detection_rules`.
- `main.py` – defines the root `click` group and most top-level commands. Subcommands use decorators `@root.command` or `@root.group`.

## Command Groups
- `kbwrap.py` – `kibana` command group for interacting with a Kibana instance (import/export rules, manage exceptions, etc.).
- `eswrap.py` – `es` command group for Elasticsearch operations such as searching and normalizing data.
- `devtools.py` – `dev` group used internally for building and packaging rules.
- `custom_rules.py` – manages custom rule lifecycle through the `custom-rules` group.
- `main.py` also defines the `typosquat` group for typosquatting related utilities.

## Supporting Modules
- `rule_loader.py`, `rule.py` – parse and validate rule TOML files.
- `packaging.py`, `navigator.py` – create packages and summary docs for releases.
- `cli_utils.py`, `misc.py` – shared helpers for prompts, clients and command options.
- `schemas/` – dataclasses and schema validation for rules and packages.
- `etc/` – configuration files (ECS schemas, version settings, etc.).

### Auth and Configuration
Commands that communicate with Kibana or Elasticsearch read authentication
details from environment variables prefixed with `DR_`. For example export
`DR_KIBANA_URL`, `DR_ELASTICSEARCH_URL`, `DR_USER`, `DR_PASSWORD` and
`DR_API_KEY` to match the provided test instance variables. The same options can
also be stored in `.detection-rules-cfg.json` or passed as command arguments.
Credentials files should never be committed.

When adding a new CLI subcommand, start in `main.py` to register it with the root group, then implement logic in a dedicated module or an existing one listed above.

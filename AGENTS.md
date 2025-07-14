# Agent Instructions: Repo Overview and CLI

This repository hosts the Elastic Security detection rules and the supporting command line tooling.

## Repository Structure
- `detection_rules/` – main Python package containing the CLI and rule management libraries.
- `lib/` – Python packages that are installed locally (`kibana` and `kql`).
- `rules/` and `rules_building_block/` – rule definitions in TOML format.
- `hunting/` – threat hunting queries with its own lightweight CLI.
- `tests/` – unit tests for the rule loader and CLI utilities.
- `docs*/` - folders containing documentation for the repository
- `docs-logs/` - a folder containing markdown files on old feature or bug fix implementations such that they can be looked up later.

## CLI Quickstart
When implementing or fixing CLI features, follow these steps and always test your new CLI features by using the workflow described below!
- Install the dependencies with `make deps > /tmp/deps.log 2>&1` and check the log file `/tmp/deps.log` for any errors. If you encounter issues, please document them in the `Issues` section below.
- Always start with an active environment `source env/detection-rules-build/bin/activate`.
- The CLI entry point is `python -m detection_rules` which runs `detection_rules.__main__:main`.
- Commands are implemented with the [click](https://click.palletsprojects.com/) framework in `detection_rules/main.py` and related modules.
- Run `python -m detection_rules --help` to view the available commands. Each subcommand also accepts `--help`.
- Always first access this test instance to validate connection if your task is to implement or fix CLI features
```sh
# test connection to Kibana
# DR_KIBANA_URL and DR_API_KEY are already set in the environment, so you can directly use them
python -m detection_rules kibana search-alerts
# the result doesnt matter as long as you do not get an error
```
-  Once you implemented or fixed CLI features test those. An example is given here on how to test a simple import and export. To avoid long executions, it is recommended to use a custom rules folder for testing like the `rules-test` folder in this repository. But mind that the elastic instance is reused by many contributors so the state might change at any time. Thus it is recommended to create a own space for testing, and deleting it aferwards again once you are done with testing. This way you can do all you need without affecting the other contributors.
```sh
# IMPORTANT: If you changed lib/* files, you need to install the new version of the package
pip install --upgrade --force-reinstall --no-deps lib/kibana # or whatever package you changed

# create a new space with some unique name, where you adjust the number to some random 4 digit number
export SPACE=test-6371

curl -X POST "$DR_KIBANA_URL/api/spaces/space" \
  -H "kbn-xsrf: true" \
  -H "Authorization: ApiKey $DR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '
{
  "id": "'"$SPACE"'", 
  "name": "'"$SPACE"'", 
  "description": "Temporary test space"
}'

# Later delete again after you are done with all tests
curl -X DELETE "$DR_KIBANA_URL/api/spaces/space/$SPACE" \
  -H "kbn-xsrf: true" \
  -H "Authorization: ApiKey $DR_API_KEY"
```
- One way to test a rule import or export would be to use this e.g.:
```sh
# test rule import
export CUSTOM_RULES_DIR=./rules-test
python -m detection_rules import-rules --space $SPACE -d $CUSTOM_RULES_DIR/rules \
    --overwrite --overwrite-action-connectors --overwrite-exceptions

# test rule export
python -m detection_rules export-rules --space $SPACE -d $CUSTOM_RULES_DIR/rules \
    -acd $CUSTOM_RULES_DIR/action_connectors -ed $CUSTOM_RULES_DIR/exceptions \
    -da SOC --export-action-connectors --export-exceptions --strip-version
```

## Genereal Information
Focus on building new CLI commands and helpers. Avoid running arbitrary commands
from the repository. For linting use ruff, e.g:
- `python -m ruff check --exit-non-zero-on-fix`

Never commit any secrets or sensitive information like environment variables!

## Network Restrictions
The container has limited outbound network access. It is not possible to install packages via pip and you cannot access the remote github repo on your own. All needed dependencies are already installed. If you miss something, adjust this readme and not it down in the issues block below.

## Documentation

When developing new CLI features or fixes, always look at the `AGENTS.md` files for general information on the repository and its structure. Also take a look at the `docs*/` folders for more detailed documentation. Especially interesting is also the `docs-logs/` folder which contains markdown files on old feature or bug fix implementations which are sometimes super useful when implementing similar features or fixes to already know where to look for or how to approach a task.

One always active task which should not be neglected is to keep the `AGENTS.md` files up to date. If you encounter issues when using functions or the cli and found a fix on how to use it, please directly document it. Basically for every issue you encounter or where you have to iterate to figure out the correct approach, just document it. The main goal of the AGENTS.md files is to reduce the time it takes to contribute to this repository and reduce the iterations needed to figure out nice workflows or how things work and are structured or how to approach new tasks. So document issues and solutions which you come across your way. This will help you and others to not run into the same issues again and again.

The second always active task is to create or update a markdown file in the `docs-logs/` folder for every feature or bug fix you implement. A focus is here to include always two things. 1. A description of the feature or bug fix, what it does, how it works and why it is needed. 2. A detailed description of the implementation, how you implemented it, what you learned, what you had to look up and where you found the information and which relevant files in this repo you changed or are needed to understand the implementation. This way you can look up the implementation later on and do not have to figure out everything again. Also it helps others to understand the implementation and how it works, so they can build on top of it or fix issues in the future.

## Issues
List issues here. Might be empty if none are known.

[![Supported Python versions](https://img.shields.io/badge/python-3.12+-yellow.svg)](https://www.python.org/downloads/)
[![Unit Tests](https://github.com/elastic/detection-rules/workflows/Unit%20Tests/badge.svg)](https://github.com/elastic/detection-rules/actions)
[![Chat](https://img.shields.io/badge/chat-%23security--detection--rules-blueviolet)](https://ela.st/slack)
[![ATT&CK navigator coverage](https://img.shields.io/badge/ATT&CK-Navigator-red.svg)](https://ela.st/detection-rules-navigator)

# Detection Rules

Detection Rules is the home for rules used by Elastic Security. This repository is used for the development, maintenance, testing, validation, and release of rules for Elastic Security’s Detection Engine.

This repository was first announced on Elastic's blog post, [Elastic Security opens public detection rules repo](https://elastic.co/blog/elastic-security-opens-public-detection-rules-repo). For additional content, see the accompanying webinar, [Elastic Security: Introducing the public repository for detection rules](https://www.elastic.co/webinars/introducing-the-public-repository-for-detection-rules).


## Table of Contents
- [Detection Rules](#detection-rules)
  - [Table of Contents](#table-of-contents)
  - [Overview of this repository](#overview-of-this-repository)
  - [Getting started](#getting-started)
  - [How to contribute](#how-to-contribute)
  - [Licensing](#licensing)
  - [Questions? Problems? Suggestions?](#questions-problems-suggestions)


## Overview of this repository

Detection Rules contains more than just static rule files. This repository also contains code for unit testing in Python and integrating with the Detection Engine in Kibana.

| folder                                          |  description                                                                        |
|------------------------------------------------ |------------------------------------------------------------------------------------ |
| [`detection_rules/`](detection_rules)           | Python module for rule parsing, validating and packaging                            |
| [`etc/`](detection_rules/etc)                   | Miscellaneous files, such as ECS and Beats schemas                                  |
| [`hunting`](./hunting/)                         | Root directory where threat hunting queries are stored                              |
| [`kibana/`](lib/kibana)                         | Python library for handling the API calls to Kibana and the Detection Engine        |
| [`kql/`](lib/kql)                               | Python library for parsing and validating Kibana Query Language                     |
| [`rta/`](rta)                                   | Red Team Automation code used to emulate attacker techniques, used for rule testing |
| [`rules/`](rules)                               | Root directory where rules are stored                                               |
| [`rules_building_block/`](rules_building_block) | Root directory where building block rules are stored                                |
| [`tests/`](tests)                               | Python code for unit testing rules                                                  |


## Getting started

Although rules can be added by manually creating `.toml` files, we don't recommend it. This repository also consists of a python module that aids rule creation and unit testing. Assuming you have Python 3.12+, run the below command to install the dependencies using the makefile:

```console
✗ make
python3.12 -m pip install --upgrade pip setuptools
Looking in indexes: https://pypi.org/simple
Requirement already satisfied: pip in /opt/homebrew/lib/python3.12/site-packages (24.0)
Requirement already satisfied: setuptools in /opt/homebrew/lib/python3.12/site-packages (69.1.1)
python3.12 -m venv ./env/detection-rules-build
./env/detection-rules-build/bin/pip install --upgrade pip setuptools
Looking in indexes: https://pypi.org/simple
Requirement already satisfied: pip in ./env/detection-rules-build/lib/python3.12/site-packages (24.0)
Collecting setuptools
  Using cached setuptools-69.1.1-py3-none-any.whl.metadata (6.2 kB)
Using cached setuptools-69.1.1-py3-none-any.whl (819 kB)
Installing collected packages: setuptools
Successfully installed setuptools-69.1.1
Installing kql and kibana packages...
...
```


Or install the dependencies using the following command:
```console
$ pip3 install ".[dev]"
Collecting jsl==0.2.4
  Downloading jsl-0.2.4.tar.gz (21 kB)
Collecting jsonschema==3.2.0
  Downloading jsonschema-3.2.0-py2.py3-none-any.whl (56 kB)
     |████████████████████████████████| 56 kB 318 kB/s
Collecting requests==2.22.0
  Downloading requests-2.22.0-py2.py3-none-any.whl (57 kB)
     |████████████████████████████████| 57 kB 1.2 MB/s
Collecting Click==7.0
  Downloading Click-7.0-py2.py3-none-any.whl (81 kB)
     |████████████████████████████████| 81 kB 2.6 MB/s
...
pip3 install packages/kibana packages/kql
```

Note: The `kibana` and `kql` packages are not available on PyPI and must be installed from the `packages` directory or `git`.

```console
pip3 install git+https://github.com/elastic/detection-rules.git#subdirectory=kibana
pip3 install git+https://github.com/elastic/detection-rules.git#subdirectory=kql

# or locally
pip3 install lib/kibana lib/kql
```

Remember, make sure to activate your virtual environment if you are using one. If installed via `make`, the associated virtual environment is created in `env/detection-rules-build/`.
If you are having trouble using a Python 3.12 environment, please see the relevant section in our [troubleshooting guide](./Troubleshooting.md).

To confirm that everything was properly installed, run with the `--help` flag
```console
$  python -m detection_rules --help

Usage: detection_rules [OPTIONS] COMMAND [ARGS]...

  Commands for detection-rules repository.

Options:
  -d, --debug / -n, --no-debug  Print full exception stacktrace on errors
  -h, --help                    Show this message and exit.

Commands:
  create-rule     Create a detection rule.
  dev             Commands for development and management by internal...
  es              Commands for integrating with Elasticsearch.
  import-rules    Import rules from json, toml, or Kibana exported rule...
  kibana          Commands for integrating with Kibana.
  mass-update     Update multiple rules based on eql results.
  normalize-data  Normalize Elasticsearch data timestamps and sort.
  rule-search     Use KQL or EQL to find matching rules.
  test            Run unit tests over all of the rules.
  toml-lint       Cleanup files with some simple toml formatting.
  validate-all    Check if all rules validates against a schema.
  validate-rule   Check if a rule staged in rules dir validates against a...
  view-rule       View an internal rule or specified rule file.
```

Note:
- If you are using a virtual environment, make sure to activate it before running the above command.
- If using Windows, you may have to also run `<venv_directory>\Scripts\pywin32_postinstall.py -install` depending on your python version.

The [contribution guide](CONTRIBUTING.md) describes how to use the `create-rule` and `test` commands to create and test a new rule when contributing to Detection Rules.

For more advanced command line interface (CLI) usage, refer to the [CLI guide](CLI.md).

## How to contribute

We welcome your contributions to Detection Rules! Before contributing, please familiarize yourself with this repository, its [directory structure](#overview-of-this-repository), and our [philosophy](PHILOSOPHY.md) about rule creation. When you're ready to contribute, read the [contribution guide](CONTRIBUTING.md) to learn how we turn detection ideas into production rules and validate with testing.

## Licensing

Everything in this repository — rules, code, RTA, etc. — is licensed under the [Elastic License v2](LICENSE.txt). These rules are designed to be used in the context of the Detection Engine within the Elastic Security application. If you’re using our [Elastic Cloud managed service](https://www.elastic.co/cloud/) or the default distribution of the Elastic Stack software that includes the [full set of free features](https://www.elastic.co/subscriptions), you’ll get the latest rules the first time you navigate to the detection engine.

Occasionally, we may want to import rules from another repository that already have a license, such as MIT or Apache 2.0. This is welcome, as long as the license permits sublicensing under the Elastic License v2. We keep those license notices in `NOTICE.txt` and sublicense as the Elastic License v2 with all other rules. We also require contributors to sign a [Contributor License Agreement](https://www.elastic.co/contributor-agreement) before contributing code to any Elastic repositories.

## Questions? Problems? Suggestions?

- Want to know more about the Detection Engine? Check out the [overview](https://www.elastic.co/guide/en/security/current/detection-engine-overview.html) in Kibana.
- This repository includes new and updated rules that have not been released yet. To see the latest set of rules released with the stack, see the [Prebuilt rule reference](https://www.elastic.co/guide/en/security/current/prebuilt-rules-downloadable-updates.html).
- If you’d like to report a false positive or other type of bug, please create a GitHub issue and check if there's an existing one first.
- Need help with Detection Rules? Post an issue or ask away in our [Security Discuss Forum](https://discuss.elastic.co/c/security/) or the **#security-detection-rules** channel within [Slack workspace](https://www.elastic.co/blog/join-our-elastic-stack-workspace-on-slack).

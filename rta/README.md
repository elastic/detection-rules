[![Supported Python versions](https://img.shields.io/badge/python-3.7+-yellow.svg)](https://www.python.org/downloads/)
[![Unit Tests](https://github.com/elastic/detection-rules/workflows/Unit%20Tests/badge.svg)](https://github.com/elastic/detection-rules/actions)
[![Chat](https://img.shields.io/badge/chat-%23security--detection--rules-blueviolet)](https://ela.st/slack)

## Red Team Automation

The repo comes with some red team automation ([RTA](./)) python scripts that runs on Windows, Mac OS, and *nix. 

```console
$   python -m rta -h
usage: rta [-h] ttp_name

positional arguments:
  ttp_name

optional arguments:
  -h, --help  show this help message and exit
```
ttp_name can be found in the [rta](./rta) directory. For example to execute ./rta/wevtutil_log_clear.py script, run command:

```console
$ python -m rta wevtutil_log_clear
```

Majority of the RTA scripts contain signal.rule.name info that maps to the Kibana Detection Signals - version 7.11 Beta

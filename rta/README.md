## Red Team Automation

[![Supported Python versions](https://img.shields.io/badge/python-3.7+-yellow.svg)](https://www.python.org/downloads/)
[![Chat](https://img.shields.io/badge/chat-%23security--detection--rules-blueviolet)](https://ela.st/slack)

The repo comes with some red team automation ([RTA](./)) python scripts that run on Windows, Mac OS, and \*nix. 
RTA scripts emulate known attacker behaviors and are an easy way too verify that your rules are active and working as expected.

```console
$   python -m rta -h
usage: rta [-h] ttp_name

positional arguments:
  ttp_name

optional arguments:
  -h, --help  show this help message and exit
```
`ttp_name` can be found in the [rta](.) directory. For example to execute `./rta/wevtutil_log_clear.py` script, run command:

```console
$ python -m rta wevtutil_log_clear
```

Most of the RTA scripts contain a comment with the rule name, in `signal.rule.name`, that maps to the Kibana Detection Signals.

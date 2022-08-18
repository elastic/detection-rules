# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import argparse
import importlib
import os

from . import get_ttp_names
from . import get_available_tests, rule_coverage

parser = argparse.ArgumentParser("rta")
parser.add_argument("-n", "--name", dest="name", help="Name of test to execute. E.g. bitsadmin_execution")
parser.add_argument("-l", "--list", dest="list", help="Print a list of available tests", action="store_true")
parser.add_argument("-r", "--rule-coverage", dest="rule_coverage",
                    help="Print rule coverage based on OS from available tests", action="store_true")
parser.add_argument("-o", "--os-filter", dest="os_filter", default="all",
                    help="Filter rule coverage summary by OS. (E.g. windows) Default: all",
                    choices=["windows", "linux", "macos"])

parsed_args, remaining = parser.parse_known_args()

if parsed_args.name:
    if parsed_args.name not in get_available_tests()[0]:
        raise ValueError(f"Unknown RTA: {parsed_args.name}")
    else:
        module = importlib.import_module("rta." + parsed_args.name)
        exit(module.main(*remaining))

elif parsed_args.list:
    get_available_tests(print_list=True, os_filter=parsed_args.os_filter)

elif parsed_args.rule_coverage:
    rule_coverage(parsed_args.os_filter)

else:
    print("Execute 'python -m rta -h' to see available options")

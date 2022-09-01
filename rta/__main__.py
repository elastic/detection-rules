# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import argparse
import importlib
import subprocess
import sys
import time
from pathlib import Path

from . import get_available_tests
from .common import CURRENT_OS


DELAY = 1
RTA_PLATFORM_TYPES = ["windows", "linux", "macos"]


def run_all():
    """Run a single RTA."""
    errors = []
    for ttp_file in get_available_tests(os_filter=CURRENT_OS):
        print(f"---- {Path(ttp_file).name} ----")
        p = subprocess.Popen([sys.executable, ttp_file])
        p.wait()
        code = p.returncode

        if p.returncode:
            errors.append((ttp_file, code))

        time.sleep(DELAY)
        print("")

    return len(errors)


def run(ttp_name: str, *args):
    """Run all RTAs compatible with OS."""
    if ttp_name not in get_available_tests().keys():
        raise ValueError(f"Unknown RTA {ttp_name}")

    module = importlib.import_module("rta." + ttp_name)
    return module.main(*args)


if __name__ == '__main__':
    parser = argparse.ArgumentParser("rta")
    parser.add_argument("-n", "--name", dest="name", help="Name of test to execute. E.g. bitsadmin_execution")
    parser.add_argument("-l", "--list", dest="list", action="store_true", help="Print a list of available tests")
    parser.add_argument("-o", "--os-filter", dest="os_filter", default="all", choices=RTA_PLATFORM_TYPES,
                        help="Filter rule coverage summary by OS. (E.g. windows) Default: all")
    parser.add_argument("--run-all", action="store_true")
    parser.add_argument("--delay", type=int, help="For run-all, the delay between executions")
    parsed_args, remaining = parser.parse_known_args()

    if parsed_args.name:
        if parsed_args.run_all:
            raise ValueError(f"Pass --ttp-name or --run-all, not both")
        else:
            rta_name = Path(parsed_args.run).stem
            exit(run(rta_name, *remaining))

    elif parsed_args.list:
        get_available_tests(print_list=True, os_filter=parsed_args.os_filter)
    elif parsed_args.run_all:
        exit(run_all())
    else:
        print("Execute 'python -m rta -h' to see available options")

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import importlib
from pathlib import Path
from typing import Dict, List

from . import common

CURRENT_DIR = Path(__file__).parent.absolute()


def get_available_tests(
    print_list: bool = False, os_filter: str = None
) -> (List, List[Dict]):
    """Get a list of available tests."""
    test_names = []
    test_metadata = []

    for file in CURRENT_DIR.rglob("*.py"):

        if file.stem not in ("common", "main") and not file.stem.startswith("_"):
            module = importlib.import_module(f"rta.{file.stem}")

            if os_filter and os_filter not in module.PLATFORMS and os_filter != "all":
                continue
            test_names.append(file.stem)
            test_metadata.append(
                {
                    "name": file.stem,
                    "uuid": module.RTA_ID,
                    "platforms": module.PLATFORMS,
                    "path": file,
                    "siem": module.TRIGGERED_RULES.get("SIEM", []),
                    "endpoint": module.TRIGGERED_RULES.get("ENDPOINT", []),
                    "tactics": module.TRIGGERED_RULES.get("TACTICS", []),
                }
            )

    if print_list:
        longest_test_name = len(max(test_names, key=len))
        header = f"{'name':{longest_test_name}} | {'platforms':<30}"

        print("Printing available tests")
        print(header)
        print("=" * len(header))

        for test in test_metadata:
            print(
                f"{test['name']:<{longest_test_name}} | {', '.join(test['platforms'])}"
            )

    return test_names, test_metadata


__all__ = "common"

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import importlib
import inspect
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from . import common

# Definitions
CURRENT_DIR = Path(__file__).resolve().parent
RULE_META_KEYS = ["rule_id", "rule_name"]

@dataclass
class RtaMetadata:
    """Metadata associated with all RTAs."""

    uuid: str
    platforms: List[str]
    path: Path = field(init=False)
    name: str = field(init=False)
    endpoint: Optional[List[Dict[str, str]]] = None
    siem: Optional[List[Dict[str, str]]] = None
    techniques: Optional[List[str]] = None

    def __post_init__(self):
        """Set the path and name based on the callee and check for platforms."""

        # Set the path of the callee
        for frame in inspect.stack():
            self.path = Path(frame.filename)
            self.name = self.path.name
            if frame.function == "<module>" and valid_rta_file(self.path):
                break

        # Check for valid platforms
        if not self.platforms and (self.endpoint or self.siem):
            raise ValueError(f"RTA {self.name} has no platforms specified but has rule info provided.")

        # Check for valid rule metadata
        self._validate_rule_metadata(self.endpoint, "endpoint")
        self._validate_rule_metadata(self.siem, "siem")

    def _validate_rule_metadata(self, rules: Optional[List[Dict[str, str]]], field_name: str):
        """Check for valid rule metadata"""
        if rules:
            for rule in rules:
                if sorted(rule.keys()) != RULE_META_KEYS:
                    raise ValueError(f"RTA {self.name} has invalid {field_name} field in metadata.")

def valid_rta_file(file_path: str) -> bool:
    return file_path.stem not in ["init", "common", "main"] and not file_path.name.startswith("_")


def get_available_tests(print_list: bool = False, os_filter: str = None) -> Dict[str, dict]:
    """Get a list of available tests."""

    test_metadata = {}

    for file in CURRENT_DIR.rglob("*.py"):

        if valid_rta_file(file):
            module = importlib.import_module(f"rta.{file.stem}")

            if os_filter and os_filter not in module.metadata.platforms and os_filter != "all":
                continue

            test_metadata[file.stem] = asdict(module.metadata)

    if print_list:
        py_ext = 3  # account for the .py ext
        longest_test_name = len(max(test_metadata.keys(), key=len)) + py_ext
        header = f"{'name':{longest_test_name}} | {'platforms':<21} | {'rule id':<36} | {'rule name':<30}"

        print("Printing available tests")
        print(header)
        print("=" * len(header))

        for test in test_metadata.values():
            rule_list = []
            if test['endpoint'] and test['siem']:
                rule_list = test['endpoint'] + test['siem']
            elif test['endpoint']:
                rule_list = test['endpoint']
            elif test['siem']:
                rule_list = test['siem']
            else:
                rule_list = [{"rule_name": "", "rule_id": ""}]
            print(f"{test['name']:<{longest_test_name}} | {', '.join(test['platforms']):<21} | {rule_list[0]['rule_id']:36} | {rule_list[0]['rule_name']}")
            for rule in rule_list[1:]:
                print(f"{'':<{longest_test_name}} | {'':<21} | {rule['rule_id']:36} | {rule['rule_name']}")

    return test_metadata


__all__ = "common"

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import glob
import importlib
import os

from pathlib import Path

from detection_rules.rule_loader import RuleCollection

from . import common

CURRENT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))


def get_available_tests(print_list=False, os_filter=None):
    test_names = []
    test_metadata = []

    for file in list(CURRENT_DIR.rglob("*.py")):
        if file.stem not in ("common", "main") and not file.stem.startswith("_"):
            module = importlib.import_module(f"rta.{file.stem}")
            if os_filter and os_filter not in module.PLATFORMS:
                continue
            test_names.append(file.stem)
            test_metadata.append({"name": file.stem, "path": file, "platforms": module.PLATFORMS})

    if print_list:
        longest_test_name = len(max(test_names, key=len))
        print("Printing available tests")
        header = f"{'name':{longest_test_name}} | {'platforms':<30}"
        print(header)
        print("=" * len(header))
        [print(f"{test['name']:<{longest_test_name}} | {', '.join(test['platforms'])}") for test in test_metadata]

    return test_names, test_metadata


def get_rta_triggered_rules() -> dict:
    # get all rtas and the rules they cover
    all_rtas = {"windows": [], "linux": [], "macos": []}
    for file in list(CURRENT_DIR.rglob("*.py")):
        if file.stem not in ("common", "main") and not file.stem.startswith("_"):
            module = importlib.import_module(f"rta.{file.stem}")
            for platform in module.PLATFORMS:
                all_rtas[platform].extend(module.TRIGGERED_RULES.get("SIEM"))
    return all_rtas


def get_os_list(rule) -> list:
    os_list = []
    if rule.contents.metadata.os_type_list:
        os_list = [r.lower() for r in rule.contents.metadata.os_list]
    elif rule.contents.data.tags:
        tags = [t.lower() for t in rule.contents.data.tags]
        core_os = ["windows", "linux", "macos"]
        for os_type in core_os:
            if os_type in tags:
                os_list.append(os_type)
    return os_list


def build_coverage_map(all_rtas, all_rules) -> dict:
    # get the rules that are not covered by each rta
    coverage_map = {"windows": {"supported": [], "unsupported": []},
                    "linux": {"supported": [], "unsupported": []},
                    "macos": {"supported": [], "unsupported": []},
                    "all": 0}
    for trule in all_rules.rules:
        rule_covered = False
        os_list = get_os_list(trule)
        for os_type in os_list:
            diag = ""
            if "production" not in trule.contents.metadata.maturity:
                if "development" in trule.contents.metadata.maturity:
                    diag = "DIAG : "
                else:
                    diag = "DEPR : "

            if trule.name in all_rtas[os_type]:
                coverage_map[os_type]["supported"].append(f"- [x] {diag}{trule.name}")
                rule_covered = True
            else:
                coverage_map[os_type]["unsupported"].append(f"- [ ] {diag}{trule.name}")
        if rule_covered:
            coverage_map["all"] += 1

    return coverage_map


def print_converage_summary(coverage_map: dict, all_rule_count: int, os_filter: str):
    # print the results
    print("\n\nCoverage Report\n")
    supported_count = coverage_map["all"]
    print(f"{supported_count} / {all_rule_count} Endpoint Rules are supported by RTAs for all OS types")
    for os_type, results in coverage_map.items():
        if os_type == os_filter or os_filter == "all":
            if os_type == "all":
                continue
            supported = results["supported"]
            unsupported = results["unsupported"]
            print(f"\n{os_type} coverage: {len(supported)} / {len(supported) + len(unsupported)}")
            print("Supported:")
            for rule in sorted(list(set(supported))):
                print(f"\t{rule}")
            print("Unsupported:")
            for rule in sorted(list(set(unsupported))):
                print(f"\t{rule}")


def rule_coverage(os_filter: str):
    # generate rta/rule_coverage summary
    all_rtas = get_rta_triggered_rules()

    # get all rules
    all_rules = RuleCollection.default()

    # build coverage map
    coverage_map = build_coverage_map(all_rtas, all_rules)

    # print summary
    all_rule_count = len(all_rules.rules)
    print_converage_summary(coverage_map, all_rule_count, os_filter)


__all__ = (
    "common"
)

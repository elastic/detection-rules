# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""RTA to rule mappings."""
import os
from collections import defaultdict

from rta import get_available_tests

from .rule import TOMLRule
from .schemas import validate_rta_mapping
from .utils import get_path, load_etc_dump, save_etc_dump

RTA_DIR = get_path("rta")
RTA_PLATFORM_TYPES = ["windows", "linux", "macos"]


class RtaMappings:
    """Rta-mapping helper class."""

    def __init__(self):
        """Rta-mapping validation and prep."""
        self.mapping: dict = load_etc_dump('rule-mapping.yml')
        self.validate()

        self._rta_mapping = defaultdict(list)
        self._remote_rta_mapping = {}
        self._rule_mappings = {}

    def validate(self):
        """Validate mapping against schema."""
        for k, v in self.mapping.items():
            validate_rta_mapping(v)

    def add_rule_to_mapping_file(self, rule, rta_name, count=0, *sources):
        """Insert a rule mapping into the mapping file."""
        mapping = self.mapping
        rule_map = {
            'count': count,
            'rta_name': rta_name,
            'rule_name': rule.name,
        }

        if sources:
            rule_map['sources'] = list(sources)

        mapping[rule.id] = rule_map
        self.mapping = dict(sorted(mapping.items()))
        save_etc_dump(self.mapping, 'rule-mapping.yml')
        return rule_map

    def get_rta_mapping(self):
        """Build the rule<-->rta mapping based off the mapping file."""
        if not self._rta_mapping:
            self._rta_mapping = self.mapping.copy()

        return self._rta_mapping

    def get_rta_files(self, rta_list=None, rule_ids=None):
        """Get the full paths to RTA files, given a list of names or rule ids."""
        full_rta_mapping = self.get_rta_mapping()
        rta_files = set()
        rta_list = set(rta_list or [])

        if rule_ids:
            for rule_id, rta_map in full_rta_mapping.items():
                if rule_id in rule_ids:
                    rta_list.update(rta_map)

        for rta_name in rta_list:
            # rip off the extension and add .py
            rta_name, _ = os.path.splitext(os.path.basename(rta_name))
            rta_path = os.path.abspath(os.path.join(RTA_DIR, rta_name + ".py"))
            if os.path.exists(rta_path):
                rta_files.add(rta_path)

        return list(sorted(rta_files))


def get_triggered_rules() -> dict:
    """Get the rules that are triggered by each RTA."""
    triggered_rules = {}
    for rta_test in list(get_available_tests().values()):
        for rule_info in rta_test.get("siem", []):
            rule_id = rule_info.get("rule_id")
            for platform in rta_test.get("platforms", []):
                triggered_rules.setdefault(platform, []).append(rule_id)
    return triggered_rules


def get_platform_list(rule: TOMLRule) -> list:
    """Get the list of OSes for a rule."""
    os_list = []
    if rule.contents.metadata.os_type_list:
        os_list = [r.lower() for r in rule.contents.metadata.os_list]
    elif rule.contents.data.tags:
        tags = [t.lower() for t in rule.contents.data.tags]
        os_list = [t for t in RTA_PLATFORM_TYPES if t in tags]
    return os_list


def build_coverage_map(triggered_rules: dict, all_rules) -> dict:
    """Get the rules that are not covered by each rta."""

    # avoid a circular import
    from .rule_loader import RuleCollection
    all_rules: RuleCollection

    coverage_map = {"all": 0}
    for rule in all_rules.rules:
        rule_covered = False
        os_list = get_platform_list(rule)

        for os_type in os_list:
            prefix = ""

            if rule.contents.metadata.maturity == "development":
                prefix = "DIAG : "
            elif rule.contents.metadata.maturity == "deprecated":
                prefix = "DEPR : "

            if rule.id in triggered_rules[os_type]:
                coverage_map.setdefault(os_type, {}).setdefault("supported", []).append(f"- [x] {prefix}{rule.name}")
                rule_covered = True
            else:
                coverage_map.setdefault(os_type, {}).setdefault("unsupported", []).append(f"- [ ] {prefix}{rule.name}")
        if rule_covered:
            coverage_map["all"] += 1

    return coverage_map


def print_converage_summary(coverage_map: dict, all_rule_count: int, os_filter: str):
    """Print the coverage summary."""
    print("\n\nCoverage Report\n")
    supported_count = coverage_map["all"]
    print(f"{supported_count} / {all_rule_count} unique detection rules are supported by RTAs for all OS types")

    for os_type, results in coverage_map.items():

        if os_type != "all" and (os_type == os_filter or os_filter == "all"):
            supported = results["supported"]
            unsupported = results["unsupported"]

            print(f"\n{os_type} coverage: {len(supported)} / {len(supported) + len(unsupported)}")
            print("Supported:")
            for rule in sorted(set(supported)):
                print(f"\t{rule}")

            print("Unsupported:")
            for rule in sorted(set(unsupported)):
                print(f"\t{rule}")

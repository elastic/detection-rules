# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""RTA to rule mappings."""
import os
from pathlib import Path
from collections import defaultdict

from .schemas import validate_rta_mapping
from .utils import load_dump, save_etc_dump

ROOT_DIR = Path(__file__).parent.parent
RTA_DIR = ROOT_DIR.joinpath("rta")
ETC_DIR = ROOT_DIR.joinpath("etc")


class RtaMappings(object):
    """Rta-mapping helper class."""

    def __init__(self):
        """Rta-mapping validation and prep."""
        self.mapping = load_dump(ETC_DIR.joinpath('rule-mapping.yml'))  # type: dict
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

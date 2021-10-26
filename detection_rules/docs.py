# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Create summary documents for a rule package."""
from collections import defaultdict
from pathlib import Path
from typing import Optional, Union

import xlsxwriter

from .attack import technique_lookup, matrix, attack_tm, tactics
from .packaging import Package
from .rule import ThreatMapping
from .rule_loader import DeprecatedCollection, RuleCollection


class PackageDocument(xlsxwriter.Workbook):
    """Excel document for summarizing a rules package."""

    def __init__(self, path, package: Package):
        """Create an excel workbook for the package."""
        self._default_format = {'font_name': 'Helvetica', 'font_size': 12}
        super(PackageDocument, self).__init__(path)

        self.package = package
        self.deprecated_rules = package.deprecated_rules
        self.production_rules = package.rules

        self.percent = self.add_format({'num_format': '0%'})
        self.bold = self.add_format({'bold': True})
        self.default_header_format = self.add_format({'bold': True, 'bg_color': '#FFBE33'})
        self.center = self.add_format({'align': 'center', 'valign': 'center'})
        self.bold_center = self.add_format({'bold': True, 'align': 'center', 'valign': 'center'})
        self.right_align = self.add_format({'align': 'right'})

        self._coverage = self._get_attack_coverage()

    def add_format(self, properties=None):
        """Add a format to the doc."""
        properties = properties or {}
        for key in self._default_format:
            if key not in properties:
                properties[key] = self._default_format[key]

        return super(PackageDocument, self).add_format(properties)

    def _get_attack_coverage(self):
        coverage = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))

        for rule in self.package.rules:
            threat = rule.contents.data.threat
            sub_dir = Path(rule.path).parent.name

            if threat:
                for entry in threat:
                    tactic = entry.tactic
                    techniques = entry.technique or []
                    for technique in techniques:
                        if technique.id in matrix[tactic.name]:
                            coverage[tactic.name][technique.id][sub_dir] += 1

        return coverage

    def populate(self):
        """Populate the different pages."""
        self.add_summary()
        self.add_rule_details()
        self.add_attack_matrix()
        self.add_rta_mapping()
        self.add_rule_details(self.deprecated_rules, 'Deprecated Rules')

    def add_summary(self):
        """Add the summary worksheet."""
        worksheet = self.add_worksheet('Summary')
        worksheet.freeze_panes(1, 0)
        worksheet.set_column(0, 0, 25)
        worksheet.set_column(1, 1, 10)

        row = 0
        worksheet.merge_range(row, 0, row, 1, "SUMMARY", self.bold_center)
        row += 1

        worksheet.write(row, 0, "Package Name")
        worksheet.write(row, 1, self.package.name, self.right_align)
        row += 1

        tactic_counts = defaultdict(int)
        for rule in self.package.rules:
            threat = rule.contents.data.threat
            if threat:
                for entry in threat:
                    tactic_counts[entry.tactic.name] += 1

        worksheet.write(row, 0, "Total Production Rules")
        worksheet.write(row, 1, len(self.production_rules))
        row += 2

        worksheet.write(row, 0, "Total Deprecated Rules")
        worksheet.write(row, 1, len(self.deprecated_rules))
        row += 1

        worksheet.write(row, 0, "Total Rules")
        worksheet.write(row, 1, len(self.package.rules))
        row += 2

        worksheet.merge_range(row, 0, row, 3, f"MITRE {attack_tm} TACTICS", self.bold_center)
        row += 1

        for tactic in tactics:
            worksheet.write(row, 0, tactic)
            worksheet.write(row, 1, tactic_counts[tactic])
            num_techniques = len(self._coverage[tactic])
            total_techniques = len(matrix[tactic])
            percent = float(num_techniques) / float(total_techniques)
            worksheet.write(row, 2, percent, self.percent)
            worksheet.write(row, 3, f'{num_techniques}/{total_techniques}', self.right_align)
            row += 1

    def add_rule_details(self, rules: Optional[Union[DeprecatedCollection, RuleCollection]] = None,
                         name='Rule Details'):
        """Add a worksheet for detailed metadata of rules."""
        if rules is None:
            rules = self.production_rules

        worksheet = self.add_worksheet(name)
        worksheet.freeze_panes(1, 1)
        headers = ('Name', 'ID', 'Version', 'Type', 'Language', 'Index', 'Tags',
                   f'{attack_tm} Tactics', f'{attack_tm} Techniques', 'Description')

        for column, header in enumerate(headers):
            worksheet.write(0, column, header, self.default_header_format)

        column_max_widths = [0 for i in range(len(headers))]
        metadata_fields = (
            'name', 'rule_id', 'version', 'type', 'language', 'index', 'tags', 'tactics', 'techniques', 'description'
        )

        for row, rule in enumerate(rules, 1):
            rule_contents = {'tactics': '', 'techniques': ''}
            if isinstance(rules, RuleCollection):
                flat_mitre = ThreatMapping.flatten(rule.contents.data.threat)
                rule_contents = {'tactics': flat_mitre.tactic_names, 'techniques': flat_mitre.technique_ids}

            rule_contents.update(rule.contents.to_api_format())

            for column, field in enumerate(metadata_fields):
                value = rule_contents.get(field)
                if value is None:
                    continue
                elif isinstance(value, list):
                    value = ', '.join(value)
                worksheet.write(row, column, value)
                column_max_widths[column] = max(column_max_widths[column], len(str(value)))

        # cap description width at 80
        column_max_widths[-1] = 80

        # this is still not perfect because the font used is not monospaced, but it gets it close
        for index, width in enumerate(column_max_widths):
            worksheet.set_column(index, index, width)

        worksheet.autofilter(0, 0, len(rules) + 1, len(headers) - 1)

    def add_rta_mapping(self):
        """Add a worksheet for the RTA/Rule RTA mapping."""
        from .rule_loader import rta_mappings

        worksheet = self.add_worksheet('RTA Mapping')
        worksheet.freeze_panes(1, 0)
        headers = ('Rule ID', 'Rule Name', 'RTA')
        for column, header in enumerate(headers):
            worksheet.write(0, column, header, self.default_header_format)

        row = 1
        for rule_id, mapping in rta_mappings.get_rta_mapping().items():
            worksheet.write(row, 0, rule_id)
            worksheet.write(row, 1, mapping['rule_name'])
            worksheet.write(row, 2, mapping['rta_name'])
            row += 1

        worksheet.set_column(0, 0, 35)
        worksheet.set_column(1, 1, 50)
        worksheet.set_column(2, 2, 35)

    def add_attack_matrix(self):
        """Add a worksheet for ATT&CK coverage."""
        worksheet = self.add_worksheet(attack_tm + ' Coverage')
        worksheet.freeze_panes(1, 0)
        header = self.add_format({'font_size': 12, 'bold': True, 'bg_color': '#005B94', 'font_color': 'white'})
        default = self.add_format({'font_size': 10, 'text_wrap': True})
        bold = self.add_format({'font_size': 10, 'bold': True, 'text_wrap': True})
        technique_url = 'https://attack.mitre.org/techniques/'

        for column, tactic in enumerate(tactics):
            worksheet.write(0, column, tactic, header)
            worksheet.set_column(column, column, 20)

            for row, technique_id in enumerate(matrix[tactic], 1):
                technique = technique_lookup[technique_id]
                fmt = bold if technique_id in self._coverage[tactic] else default

                coverage = self._coverage[tactic].get(technique_id)
                coverage_str = ''
                if coverage:
                    coverage_str = '\n\n'
                    coverage_str += '\n'.join(f'{sub_dir}: {count}' for sub_dir, count in coverage.items())

                worksheet.write_url(row, column, technique_url + technique_id.replace('.', '/'), cell_format=fmt,
                                    string=technique['name'], tip=f'{technique_id}{coverage_str}')

        worksheet.autofilter(0, 0, max([len(v) for k, v in matrix.items()]) + 1, len(tactics) - 1)

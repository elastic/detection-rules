# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Create summary documents for a rule package."""
import itertools
import re
import shutil
import textwrap
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Optional, Union

import json
import xlsxwriter

from .attack import technique_lookup, matrix, attack_tm, tactics
from .packaging import Package
from .rule_loader import DeprecatedCollection, RuleCollection
from .rule import ThreatMapping, TOMLRule
from .semver import Version


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


# Documentation generation of product docs https://www.elastic.co/guide/en/security/7.15/detection-engine-overview.html


class AsciiDoc:

    @classmethod
    def bold_kv(cls, key: str, value: str):
        return f'*{key}*: {value}'

    @classmethod
    def description_list(cls, value: Dict[str, str], linesep='\n\n'):
        return f'{linesep}'.join(f'{k}::\n{v}' for k, v in value.items())

    @classmethod
    def bulleted(cls, value: str, depth=1):
        return f'{"*" * depth} {value}'

    @classmethod
    def bulleted_list(cls, values: Iterable):
        return '* ' + '\n* '.join(values)

    @classmethod
    def code(cls, value: str, code='js'):
        line_sep = "-" * 34
        return f'[source, {code}]\n{line_sep}\n{value}\n{line_sep}'

    @classmethod
    def title(cls, depth: int, value: str):
        return f'{"=" * depth} {value}'

    @classmethod
    def inline_anchor(cls, value: str):
        return f'[[{value}]]'

    @classmethod
    def table(cls, data: dict) -> str:
        entries = [f'| {k} | {v}' for k, v in data.items()]
        table = ['[width="100%"]', '|==='] + entries + ['|===']
        return '\n'.join(table)


class SecurityDocs:
    """Base class for security doc generation."""


class KibanaSecurityDocs:
    """Generate docs for prebuilt rules in Elastic documentation."""

    @staticmethod
    def cmp_value(value):
        if isinstance(value, list):
            cmp_new = tuple(value)
        elif isinstance(value, dict):
            cmp_new = json.dumps(value, sort_keys=True, indent=2)
        else:
            cmp_new = value

        return cmp_new


class IntegrationSecurityDocs:
    """Generate docs for prebuilt rules in Elastic documentation."""

    def __init__(self, registry_version: str, directory: Path, overwrite=False,
                 updated_rules: Optional[Dict[str, TOMLRule]] = None, new_rules: Optional[Dict[str, TOMLRule]] = None,
                 deprecated_rules: Optional[Dict[str, TOMLRule]] = None):
        self.new_rules = new_rules
        self.updated_rules = updated_rules
        self.deprecated_rules = deprecated_rules
        self.included_rules = list(itertools.chain(new_rules.values(),
                                                   updated_rules.values(),
                                                   deprecated_rules.values()))

        self.registry_version_str, self.base_name, self.prebuilt_rule_base = self.parse_registry(registry_version)
        self.package_directory = directory / self.base_name

        if overwrite:
            shutil.rmtree(self.package_directory, ignore_errors=True)

        self.package_directory.mkdir(parents=True, exist_ok=overwrite)

    @staticmethod
    def parse_registry(registry_version: str) -> (str, str, str):
        registry_version = Version(registry_version)
        short_registry_version = [str(n) for n in registry_version[:3]]
        registry_version_str = '.'.join(short_registry_version)
        base_name = "-".join(short_registry_version)
        prebuilt_rule_base = f'prebuilt-rule-{base_name}'

        return registry_version_str, base_name, prebuilt_rule_base

    def generate_appendix(self):
        # appendix
        appendix = self.package_directory / f'prebuilt-rules-{self.base_name}-appendix.asciidoc'

        appendix_header = textwrap.dedent(f"""
        ["appendix",role="exclude",id="prebuilt-rule-{self.base_name}-prebuilt-rules-{self.base_name}-appendix"]
        = Downloadable rule update v{self.registry_version_str}

        This section lists all updates associated with version {self.registry_version_str} of the Fleet integration *Prebuilt Security Detection Rules*.

        """).lstrip()  # noqa: E501

        include_format = f'include::{self.prebuilt_rule_base}-' + '{}.asciidoc[]'
        appendix_lines = [appendix_header] + [include_format.format(name_to_title(r.name)) for r in self.included_rules]
        appendix_str = '\n'.join(appendix_lines) + '\n'
        appendix.write_text(appendix_str)

    def generate_summary(self):
        summary = self.package_directory / f'prebuilt-rules-{self.base_name}-summary.asciidoc'

        summary_header = textwrap.dedent(f"""
        [[prebuilt-rule-{self.base_name}-prebuilt-rules-{self.base_name}-summary]]
        [role="xpack"]
        == Update v{self.registry_version_str}

        This section lists all updates associated with version {self.registry_version_str} of the Fleet integration *Prebuilt Security Detection Rules*.


        [width="100%",options="header"]
        |==============================================
        |Rule |Description |Status |Version
        """).lstrip()  # noqa: E501

        rule_entries = []
        for rule in self.included_rules:
            title_name = name_to_title(rule.name)
            status = 'new' if rule.id in self.new_rules else 'update' if rule.id in self.updated_rules else 'deprecated'
            description = rule.contents.to_api_format()['description']
            version = rule.contents.autobumped_version
            rule_entries.append(f'|<<prebuilt-rule-{self.base_name}-{title_name}, {rule.name}>> '
                                f'| {description} | {status} | {version} \n')

        summary_lines = [summary_header] + rule_entries + ['|==============================================']
        summary_str = '\n'.join(summary_lines) + '\n'
        summary.write_text(summary_str)

    def generate_rule_details(self):
        for rule in self.included_rules:
            rule_detail = IntegrationRuleDetail(rule.id, rule.contents.to_api_format(), {}, self.base_name)
            rule_path = self.package_directory / f'{self.prebuilt_rule_base}-{name_to_title(rule.name)}.asciidoc'
            rule_path.write_text(rule_detail.generate())

    def generate_manual_updates(self):
        update_file = self.package_directory / 'manual-updates.json'
        updates = {}

        # update downloadable rule updates entry
        # https://www.elastic.co/guide/en/security/current/prebuilt-rules-downloadable-updates.html
        today = datetime.today().strftime('%d %b %Y')

        updates['detections/prebuilt-rules/prebuilt-rules-downloadable-updates.asciidoc'] = {
            'update_table_entry': (f'|<<prebuilt-rule-{self.base_name}-prebuilt-rules-{self.base_name}-summary, '
                                   f'{self.registry_version_str}>> | {today} | {len(self.new_rules)} | '
                                   f'{len(self.updated_rules)} | '),
            'update_table_include': (f'include::downloadable-packages/{self.base_name}/'
                                     f'prebuilt-rules-{self.base_name}-summary.asciidoc[leveloffset=+1]')
        }

        updates['index.asciidoc'] = {
            'update_index_include': (f'include::detections/prebuilt-rules/downloadable-packages/{self.base_name}/'
                                     f'prebuilt-rules-{self.base_name}-appendix.asciidoc[]')
        }

        update_file.write_text(json.dumps(updates, indent=2))

    def generate(self) -> Path:
        self.generate_appendix()
        self.generate_summary()
        self.generate_rule_details()
        self.generate_manual_updates()
        return self.package_directory


class IntegrationRuleDetail:
    """Rule detail page generation."""

    def __init__(self, rule_id: str, rule: dict, changelog: Dict[str, dict], package_str: str):
        self.rule_id = rule_id
        self.rule = rule
        self.changelog = changelog
        self.package = package_str
        self.rule_title = f'prebuilt-rule-{self.package}-{name_to_title(self.rule["name"])}'

        # set some defaults
        self.rule.setdefault('max_signals', 100)
        self.rule.setdefault('interval', '5m')

    def generate(self) -> str:
        """Generate the rule detail page."""
        page = [
            AsciiDoc.inline_anchor(self.rule_title),
            AsciiDoc.title(3, self.rule['name']),
            '',
            self.rule['description'],
            '',
            self.metadata_str(),
            ''
        ]
        if 'note' in self.rule:
            page.extend([self.guide_str(), ''])
        if 'query' in self.rule:
            page.extend([self.query_str(), ''])
        if 'threat' in self.rule:
            page.extend([self.threat_mapping_str(), ''])

        return '\n'.join(page)

    def metadata_str(self) -> str:
        fields = {
            'type': 'Rule type',
            'index': 'Rule indices',
            'severity': 'Severity',
            'risk_score': 'Risk score',
            'interval': 'Runs every',
            'from': 'Searches indices from',
            'max_signals': 'Maximum alerts per execution',
            'references': 'References',
            'tags': 'Tags',
            'version': 'Version',
            'author': 'Rule authors',
            'license': 'Rule license'
        }
        values = []

        for field, friendly_name in fields.items():
            value = self.rule.get(field) or self.changelog.get(field)
            if isinstance(value, list):
                str_value = f'\n\n{AsciiDoc.bulleted_list(value)}'
            else:
                str_value = str(value)

            if field == 'from':
                str_value += ' ({ref}/common-options.html#date-math[Date Math format], see also <<rule-schedule, ' \
                             '`Additional look-back time`>>)'

            values.extend([AsciiDoc.bold_kv(friendly_name, str_value), ''])

        return '\n'.join(values)

    def guide_str(self) -> str:
        return f'{AsciiDoc.title(4, "Investigation guide")}\n\n\n{AsciiDoc.code(self.rule["note"], code="markdown")}'

    def query_str(self) -> str:
        # TODO: code=sql - would require updating existing
        return f'{AsciiDoc.title(4, "Rule query")}\n\n\n{AsciiDoc.code(self.rule["query"])}'

    def threat_mapping_str(self) -> str:
        values = [AsciiDoc.bold_kv('Framework', 'MITRE ATT&CK^TM^'), '']

        for entry in self.rule['threat']:
            tactic = entry['tactic']
            entry_values = [
                AsciiDoc.bulleted('Tactic:'),
                AsciiDoc.bulleted(f'Name: {tactic["name"]}', depth=2),
                AsciiDoc.bulleted(f'ID: {tactic["id"]}', depth=2),
                AsciiDoc.bulleted(f'Reference URL: {tactic["reference"]}', depth=2)
            ]

            techniques = entry.get('technique', [])
            for technique in techniques:
                entry_values.extend([
                    AsciiDoc.bulleted('Technique:'),
                    AsciiDoc.bulleted(f'Name: {technique["name"]}', depth=2),
                    AsciiDoc.bulleted(f'ID: {technique["id"]}', depth=2),
                    AsciiDoc.bulleted(f'Reference URL: {technique["reference"]}', depth=2)
                ])

                subtechniques = technique.get('subtechnique', [])
                for subtechnique in subtechniques:
                    entry_values.extend([
                        AsciiDoc.bulleted('Sub-technique:'),
                        AsciiDoc.bulleted(f'Name: {subtechnique["name"]}', depth=2),
                        AsciiDoc.bulleted(f'ID: {subtechnique["id"]}', depth=2),
                        AsciiDoc.bulleted(f'Reference URL: {subtechnique["reference"]}', depth=2)
                    ])

            values.extend(entry_values)

        return '\n'.join(values)


def name_to_title(name: str) -> str:
    """Convert a rule name to tile."""
    initial = re.sub(r'[^\w]|_', r'-', name.lower().strip())
    return re.sub(r'-{2,}', '-', initial).strip('-')

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Create summary documents for a rule package."""

import itertools
import json
import re
import shutil
import textwrap
import typing
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import xlsxwriter  # type: ignore[reportMissingTypeStubs]
import xlsxwriter.format  # type: ignore[reportMissingTypeStubs]
from semver import Version

from .attack import attack_tm, matrix, tactics, technique_lookup
from .packaging import Package
from .rule import DeprecatedRule, ThreatMapping, TOMLRule
from .rule_loader import DeprecatedCollection, RuleCollection
from .utils import load_etc_dump, save_etc_dump

REPO_DOCS_DIR = "docs-dev"


class PackageDocument(xlsxwriter.Workbook):
    """Excel document for summarizing a rules package."""

    def __init__(self, path: str, package: Package) -> None:
        """Create an excel workbook for the package."""
        self._default_format = {"font_name": "Helvetica", "font_size": 12}
        super().__init__(path)  # type: ignore[reportUnknownMemberType]

        self.package = package
        self.deprecated_rules = package.deprecated_rules
        self.production_rules = package.rules

        self.percent = self.add_format({"num_format": "0%"})
        self.bold = self.add_format({"bold": True})
        self.default_header_format = self.add_format({"bold": True, "bg_color": "#FFBE33"})
        self.center = self.add_format({"align": "center", "valign": "center"})
        self.bold_center = self.add_format({"bold": True, "align": "center", "valign": "center"})
        self.right_align = self.add_format({"align": "right"})

        self._coverage = self._get_attack_coverage()

    def add_format(self, properties: dict[str, Any] | None = None) -> xlsxwriter.format.Format:
        """Add a format to the doc."""
        properties = properties or {}
        for key in self._default_format:
            if key not in properties:
                properties[key] = self._default_format[key]

        return super().add_format(properties)  # type: ignore[reportUnknownMemberType]

    def _get_attack_coverage(self) -> dict[str, Any]:
        coverage: dict[str, dict[str, dict[str, int]]] = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))

        for rule in self.package.rules:
            threat = rule.contents.data.threat
            if not rule.path:
                raise ValueError("No rule path found")

            sub_dir = Path(rule.path).parent.name

            if threat:
                for entry in threat:
                    tactic = entry.tactic
                    techniques = entry.technique or []
                    for technique in techniques:
                        if technique.id in matrix[tactic.name]:
                            coverage[tactic.name][technique.id][sub_dir] += 1

        return coverage

    def populate(self) -> None:
        """Populate the different pages."""
        self.add_summary()
        self.add_rule_details()
        self.add_attack_matrix()
        self.add_rule_details(self.deprecated_rules, "Deprecated Rules")

    @typing.no_type_check
    def add_summary(self) -> None:
        """Add the summary worksheet."""
        worksheet = self.add_worksheet("Summary")
        worksheet.freeze_panes(1, 0)
        worksheet.set_column(0, 0, 25)
        worksheet.set_column(1, 1, 10)

        row = 0
        worksheet.merge_range(row, 0, row, 1, "SUMMARY", self.bold_center)
        row += 1

        _ = worksheet.write(row, 0, "Package Name")
        _ = worksheet.write(row, 1, self.package.name, self.right_align)
        row += 1

        tactic_counts: dict[str, int] = defaultdict(int)
        for rule in self.package.rules:
            threat = rule.contents.data.threat
            if threat:
                for entry in threat:
                    tactic_counts[entry.tactic.name] += 1

        _ = worksheet.write(row, 0, "Total Production Rules")
        _ = worksheet.write(row, 1, len(self.production_rules))
        row += 2

        _ = worksheet.write(row, 0, "Total Deprecated Rules")
        _ = worksheet.write(row, 1, len(self.deprecated_rules))
        row += 1

        _ = worksheet.write(row, 0, "Total Rules")
        _ = worksheet.write(row, 1, len(self.package.rules))
        row += 2

        worksheet.merge_range(row, 0, row, 3, f"MITRE {attack_tm} TACTICS", self.bold_center)
        row += 1

        for tactic in tactics:
            _ = worksheet.write(row, 0, tactic)
            _ = worksheet.write(row, 1, tactic_counts[tactic])
            num_techniques = len(self._coverage[tactic])
            total_techniques = len(matrix[tactic])
            percent = float(num_techniques) / float(total_techniques)
            _ = worksheet.write(row, 2, percent, self.percent)
            _ = worksheet.write(row, 3, f"{num_techniques}/{total_techniques}", self.right_align)
            row += 1

    def add_rule_details(
        self,
        rules: DeprecatedCollection | RuleCollection | None = None,
        name: str = "Rule Details",
    ) -> None:
        """Add a worksheet for detailed metadata of rules."""
        if rules is None:
            rules = self.production_rules

        worksheet = self.add_worksheet(name)  # type: ignore[reportUnknownVariableType]
        worksheet.freeze_panes(1, 1)  # type: ignore[reportUnknownVariableType]
        headers = (
            "Name",
            "ID",
            "Version",
            "Type",
            "Language",
            "Index",
            "Tags",
            f"{attack_tm} Tactics",
            f"{attack_tm} Techniques",
            "Description",
        )

        for column, header in enumerate(headers):
            _ = worksheet.write(0, column, header, self.default_header_format)  # type: ignore[reportUnknownMemberType]

        column_max_widths = [0 for _ in range(len(headers))]
        metadata_fields = (
            "name",
            "rule_id",
            "version",
            "type",
            "language",
            "index",
            "tags",
            "tactics",
            "techniques",
            "description",
        )

        for row, rule in enumerate(rules, 1):
            rule_contents = {"tactics": "", "techniques": ""}
            if isinstance(rules, RuleCollection):
                flat_mitre = ThreatMapping.flatten(rule.contents.data.threat)  # type: ignore[reportAttributeAccessIssue]
                rule_contents = {"tactics": flat_mitre.tactic_names, "techniques": flat_mitre.technique_ids}

            rule_contents.update(rule.contents.to_api_format())

            for column, field in enumerate(metadata_fields):
                value = rule_contents.get(field)
                if value is None:
                    continue
                if isinstance(value, list):
                    value = ", ".join(value)
                _ = worksheet.write(row, column, value)  # type: ignore[reportUnknownMemberType]
                column_max_widths[column] = max(column_max_widths[column], len(str(value)))

        # cap description width at 80
        column_max_widths[-1] = 80

        # this is still not perfect because the font used is not monospaced, but it gets it close
        for index, width in enumerate(column_max_widths):
            _ = worksheet.set_column(index, index, width)  # type: ignore[reportUnknownMemberType]

        _ = worksheet.autofilter(0, 0, len(rules) + 1, len(headers) - 1)  # type: ignore[reportUnknownMemberType]

    def add_attack_matrix(self) -> None:
        """Add a worksheet for ATT&CK coverage."""
        worksheet = self.add_worksheet(attack_tm + " Coverage")  # type: ignore[reportUnknownMemberType]
        worksheet.freeze_panes(1, 0)  # type: ignore[reportUnknownMemberType]
        header = self.add_format({"font_size": 12, "bold": True, "bg_color": "#005B94", "font_color": "white"})
        default = self.add_format({"font_size": 10, "text_wrap": True})
        bold = self.add_format({"font_size": 10, "bold": True, "text_wrap": True})
        technique_url = "https://attack.mitre.org/techniques/"

        for column, tactic in enumerate(tactics):
            _ = worksheet.write(0, column, tactic, header)  # type: ignore[reportUnknownMemberType]
            _ = worksheet.set_column(column, column, 20)  # type: ignore[reportUnknownMemberType]

            for row, technique_id in enumerate(matrix[tactic], 1):
                technique = technique_lookup[technique_id]
                fmt = bold if technique_id in self._coverage[tactic] else default

                coverage = self._coverage[tactic].get(technique_id)
                coverage_str = ""
                if coverage:
                    coverage_str = "\n\n"
                    coverage_str += "\n".join(f"{sub_dir}: {count}" for sub_dir, count in coverage.items())

                _ = worksheet.write_url(  # type: ignore[reportUnknownMemberType]
                    row,
                    column,
                    technique_url + technique_id.replace(".", "/"),
                    cell_format=fmt,
                    string=technique["name"],
                    tip=f"{technique_id}{coverage_str}",
                )

        _ = worksheet.autofilter(0, 0, max([len(v) for _, v in matrix.items()]) + 1, len(tactics) - 1)  # type: ignore[reportUnknownMemberType]


# product rule docs
# Documentation generation of product docs https://www.elastic.co/guide/en/security/7.15/detection-engine-overview.html


class AsciiDoc:
    @classmethod
    def bold_kv(cls, key: str, value: str) -> str:
        return f"*{key}*: {value}"

    @classmethod
    def description_list(cls, value: dict[str, str], linesep: str = "\n\n") -> str:
        return f"{linesep}".join(f"{k}::\n{v}" for k, v in value.items())

    @classmethod
    def bulleted(cls, value: str, depth: int = 1) -> str:
        return f"{'*' * depth} {value}"

    @classmethod
    def bulleted_list(cls, values: list[str]) -> str:
        return "* " + "\n* ".join(values)

    @classmethod
    def code(cls, value: str, code: str = "js") -> str:
        line_sep = "-" * 34
        return f"[source, {code}]\n{line_sep}\n{value}\n{line_sep}"

    @classmethod
    def title(cls, depth: int, value: str) -> str:
        return f"{'=' * depth} {value}"

    @classmethod
    def inline_anchor(cls, value: str) -> str:
        return f"[[{value}]]"

    @classmethod
    def table(cls, data: dict[str, Any]) -> str:
        entries = [f"| {k} | {v}" for k, v in data.items()]
        table = ['[width="100%"]', "|===", *entries, "|==="]
        return "\n".join(table)


class SecurityDocs:
    """Base class for security doc generation."""


class KibanaSecurityDocs:
    """Generate docs for prebuilt rules in Elastic documentation."""

    @staticmethod
    def cmp_value(value: Any) -> Any:
        if isinstance(value, list):
            cmp_new = tuple(value)  # type: ignore[reportUnknownArgumentType]
        elif isinstance(value, dict):
            cmp_new = json.dumps(value, sort_keys=True, indent=2)
        else:
            cmp_new = value

        return cmp_new  # type: ignore[reportUnknownVariableType]


class IntegrationSecurityDocs:
    """Generate docs for prebuilt rules in Elastic documentation."""

    def __init__(  # noqa: PLR0913
        self,
        registry_version: str,
        directory: Path,
        overwrite: bool = False,
        updated_rules: dict[str, TOMLRule] | None = None,
        new_rules: dict[str, TOMLRule] | None = None,
        deprecated_rules: dict[str, DeprecatedRule] | None = None,
        update_message: str = "",
    ) -> None:
        self.new_rules = new_rules
        self.updated_rules = updated_rules
        self.deprecated_rules = deprecated_rules
        self.included_rules: list[TOMLRule | DeprecatedRule] = []
        if new_rules:
            self.included_rules += new_rules.values()

        if updated_rules:
            self.included_rules += updated_rules.values()

        if deprecated_rules:
            self.included_rules += deprecated_rules.values()

        all_rules = RuleCollection.default().rules
        self.sorted_rules = sorted(all_rules, key=lambda rule: rule.name)
        self.registry_version_str, self.base_name, self.prebuilt_rule_base = self.parse_registry(registry_version)
        self.directory = directory
        self.package_directory = (
            directory / "docs" / "detections" / "prebuilt-rules" / "downloadable-packages" / self.base_name
        )
        self.rule_details = directory / "docs" / "detections" / "prebuilt-rules" / "rule-details"
        self.update_message = update_message

        if overwrite:
            shutil.rmtree(self.package_directory, ignore_errors=True)

        self.package_directory.mkdir(parents=True, exist_ok=overwrite)

    @staticmethod
    def parse_registry(registry_version_val: str) -> tuple[str, str, str]:
        registry_version = Version.parse(registry_version_val, optional_minor_and_patch=True)

        parts = registry_version[:3]
        short_registry_version = [str(n) for n in parts]  # type: ignore[reportOptionalIterable]
        registry_version_str = ".".join(short_registry_version)
        base_name = "-".join(short_registry_version)
        prebuilt_rule_base = f"prebuilt-rule-{base_name}"

        return registry_version_str, base_name, prebuilt_rule_base

    def generate_appendix(self) -> None:
        # appendix
        appendix = self.package_directory / f"prebuilt-rules-{self.base_name}-appendix.asciidoc"

        appendix_header = textwrap.dedent(f"""
        ["appendix",role="exclude",id="prebuilt-rule-{self.base_name}-prebuilt-rules-{self.base_name}-appendix"]
        = Downloadable rule update v{self.registry_version_str}

        This section lists all updates associated with version {self.registry_version_str} of the Fleet integration *Prebuilt Security Detection Rules*.

        """).lstrip()  # noqa: E501

        include_format = f"include::{self.prebuilt_rule_base}-" + "{}.asciidoc[]"
        appendix_lines = [appendix_header] + [include_format.format(name_to_title(r.name)) for r in self.included_rules]  # type: ignore[reportArgumentType]
        appendix_str = "\n".join(appendix_lines) + "\n"
        _ = appendix.write_text(appendix_str)

    def generate_summary(self) -> None:
        summary = self.package_directory / f"prebuilt-rules-{self.base_name}-summary.asciidoc"

        summary_header = textwrap.dedent(f"""
        [[prebuilt-rule-{self.base_name}-prebuilt-rules-{self.base_name}-summary]]
        [role="xpack"]
        == Update v{self.registry_version_str}

        This section lists all updates associated with version {self.registry_version_str} of the Fleet integration *Prebuilt Security Detection Rules*.


        [width="100%",options="header"]
        |==============================================
        |Rule |Description |Status |Version
        """).lstrip()  # noqa: E501

        rule_entries: list[str] = []
        for rule in self.included_rules:
            if rule.contents.metadata.get("maturity") == "development":
                continue
            title_name = name_to_title(rule.name)  # type: ignore[reportArgumentType]

            if self.new_rules and rule.id in self.new_rules:
                status = "new"
            elif self.updated_rules and rule.id in self.updated_rules:
                status = "update"
            else:
                status = "deprecated"

            description = rule.contents.to_api_format()["description"]
            version = rule.contents.autobumped_version
            rule_entries.append(
                f"|<<prebuilt-rule-{self.base_name}-{title_name}, {rule.name}>> "
                f"| {description} | {status} | {version} \n"
            )

        summary_lines = [summary_header, *rule_entries, "|=============================================="]
        summary_str = "\n".join(summary_lines) + "\n"
        _ = summary.write_text(summary_str)

    def generate_rule_reference(self) -> None:
        """Generate rule reference page for prebuilt rules."""
        summary = self.directory / "docs" / "detections" / "prebuilt-rules" / "prebuilt-rules-reference.asciidoc"
        rule_list = self.directory / "docs" / "detections" / "prebuilt-rules" / "rule-desc-index.asciidoc"

        summary_header = textwrap.dedent("""
        [[prebuilt-rules]]
        [role="xpack"]
        == Prebuilt rule reference

        This section lists all available prebuilt rules.

        IMPORTANT: To run {ml} prebuilt rules, you must have the
        https://www.elastic.co/subscriptions[appropriate license] or use a
        {ess-trial}[Cloud] deployment. All {ml} prebuilt rules are tagged with `ML`,
        and their rule type is `machine_learning`.

        [width="100%",options="header"]
        |==============================================
        |Rule |Description |Tags |Added |Version

        """).lstrip()

        rule_entries: list[str] = []
        rule_includes: list[str] = []

        for rule in self.sorted_rules:
            if isinstance(rule, DeprecatedRule):
                continue
            if rule.contents.metadata.get("maturity") == "development":
                continue
            title_name = name_to_title(rule.name)

            # skip rules not built for this package
            built_rules = [x.name for x in self.rule_details.glob("*.asciidoc")]
            if f"{title_name}.asciidoc" not in built_rules:
                continue

            rule_includes.append(f"include::rule-details/{title_name}.asciidoc[]")
            tags = ", ".join(f"[{tag}]" for tag in rule.contents.data.tags)  # type: ignore[reportOptionalIterable]
            description = rule.contents.to_api_format()["description"]
            version = rule.contents.autobumped_version
            added = rule.contents.metadata.min_stack_version
            rule_entries.append(f"|<<{title_name}, {rule.name}>> |{description} |{tags} |{added} |{version}\n")

        summary_lines = [summary_header, *rule_entries, "|=============================================="]
        summary_str = "\n".join(summary_lines) + "\n"
        _ = summary.write_text(summary_str)

        # update rule-desc-index.asciidoc
        _ = rule_list.write_text("\n".join(rule_includes))

    def generate_rule_details(self) -> None:
        """Generate rule details for each prebuilt rule."""
        included_rules = [x.name for x in self.included_rules]
        for rule in self.sorted_rules:
            if rule.contents.metadata.get("maturity") == "development":
                continue
            rule_detail = IntegrationRuleDetail(rule.id, rule.contents.to_api_format(), {}, self.base_name)
            rule_path = self.package_directory / f"{self.prebuilt_rule_base}-{name_to_title(rule.name)}.asciidoc"
            prebuilt_rule_path = self.rule_details / f"{name_to_title(rule.name)}.asciidoc"

            if rule.name in included_rules:
                # only include updates
                _ = rule_path.write_text(rule_detail.generate())

            # add all available rules to the rule details directory
            _ = prebuilt_rule_path.write_text(rule_detail.generate(title=f"{name_to_title(rule.name)}"))

    def generate_manual_updates(self) -> None:
        """
        Generate manual updates for prebuilt rules downloadable updates and index.
        """
        updates = {}

        # Update downloadable rule updates entry
        today = datetime.today().strftime("%d %b %Y")  # noqa: DTZ002

        updates["downloadable-updates.asciidoc"] = {
            "table_entry": (
                f"|<<prebuilt-rule-{self.base_name}-prebuilt-rules-{self.base_name}-summary, "
                f"{self.registry_version_str}>> | {today} | {len(self.new_rules or [])} | "
                f"{len(self.updated_rules or [])} | "
            ),
            "table_include": (
                f"include::downloadable-packages/{self.base_name}/"
                f"prebuilt-rules-{self.base_name}-summary.asciidoc[leveloffset=+1]"
            ),
        }

        updates["index.asciidoc"] = {
            "index_include": (
                f"include::detections/prebuilt-rules/downloadable-packages/{self.base_name}/"
                f"prebuilt-rules-{self.base_name}-appendix.asciidoc[]"
            )
        }

        # Add index.asciidoc:index_include in docs/index.asciidoc
        docs_index = self.package_directory.parent.parent.parent.parent / "index.asciidoc"
        _ = docs_index.write_text(docs_index.read_text() + "\n" + updates["index.asciidoc"]["index_include"] + "\n")

        # Add table_entry to docs/detections/prebuilt-rules/prebuilt-rules-downloadable-updates.asciidoc
        downloadable_updates = self.package_directory.parent.parent / "prebuilt-rules-downloadable-updates.asciidoc"
        version = Version.parse(self.registry_version_str)
        last_version = f"{version.major}.{version.minor - 1}"
        update_url = f"https://www.elastic.co/guide/en/security/{last_version}/prebuilt-rules-downloadable-updates.html"
        summary_header = textwrap.dedent(f"""
        [[prebuilt-rules-downloadable-updates]]
        [role="xpack"]
        == Downloadable rule updates

        This section lists all updates to prebuilt detection rules, made available with the *Prebuilt Security Detection Rules* integration in Fleet.

        To update your installed rules to the latest versions, follow the instructions in <<update-prebuilt-rules>>.

        For previous rule updates, please navigate to the {update_url}[last version].

        [width="100%",options="header"]
        |==============================================
        |Update version |Date | New rules | Updated rules | Notes

        """).lstrip()  # noqa: E501
        new_content = updates["downloadable-updates.asciidoc"]["table_entry"] + "\n" + self.update_message
        self.add_content_to_table_top(downloadable_updates, summary_header, new_content)

        # Add table_include to/docs/detections/prebuilt-rules/prebuilt-rules-downloadable-updates.asciidoc
        # Reset the historic information at the beginning of each minor version
        historic_data = downloadable_updates.read_text() if Version.parse(self.registry_version_str).patch > 1 else ""
        _ = downloadable_updates.write_text(
            historic_data + updates["downloadable-updates.asciidoc"]["table_include"] + "\n"
        )

    def add_content_to_table_top(self, file_path: Path, summary_header: str, new_content: str) -> None:
        """Insert content at the top of a Markdown table right after the specified header."""
        file_contents = file_path.read_text()

        # Find the header in the file
        header = "|Update version |Date | New rules | Updated rules | Notes\n"
        header_index = file_contents.find(header)

        if header_index == -1:
            raise ValueError("Header not found in the file")

        # Calculate the position to insert new content
        insert_position = header_index + len(header)

        # Insert the new content at the insert_position
        updated_contents = summary_header + f"\n{new_content}\n" + file_contents[insert_position:]

        # Write the updated contents back to the file
        _ = file_path.write_text(updated_contents)

    def generate(self) -> Path:
        self.generate_appendix()
        self.generate_summary()
        self.generate_rule_details()
        self.generate_rule_reference()
        self.generate_manual_updates()
        return self.package_directory


class IntegrationRuleDetail:
    """Rule detail page generation."""

    def __init__(
        self,
        rule_id: str,
        rule: dict[str, Any],
        changelog: dict[str, dict[str, Any]],
        package_str: str,
    ) -> None:
        self.rule_id = rule_id
        self.rule = rule
        self.changelog = changelog
        self.package = package_str
        self.rule_title = f"prebuilt-rule-{self.package}-{name_to_title(self.rule['name'])}"

        # set some defaults
        self.rule.setdefault("max_signals", 100)
        self.rule.setdefault("interval", "5m")

    def generate(self, title: str | None = None) -> str:
        """Generate the rule detail page."""
        title = title or self.rule_title
        page = [
            AsciiDoc.inline_anchor(title),
            AsciiDoc.title(3, self.rule["name"]),
            "",
            self.rule["description"],
            "",
            self.metadata_str(),
            "",
        ]
        if "note" in self.rule:
            page.extend([self.guide_str(), ""])
        if "setup" in self.rule:
            page.extend([self.setup_str(), ""])
        if "query" in self.rule:
            page.extend([self.query_str(), ""])
        if "threat" in self.rule:
            page.extend([self.threat_mapping_str(), ""])

        return "\n".join(page)

    def metadata_str(self) -> str:
        """Add the metadata section to the rule detail page."""
        fields = {
            "type": "Rule type",
            "index": "Rule indices",
            "severity": "Severity",
            "risk_score": "Risk score",
            "interval": "Runs every",
            "from": "Searches indices from",
            "max_signals": "Maximum alerts per execution",
            "references": "References",
            "tags": "Tags",
            "version": "Version",
            "author": "Rule authors",
            "license": "Rule license",
        }
        values: list[str] = []

        for field, friendly_name in fields.items():
            value = self.rule.get(field) or self.changelog.get(field)
            if value is None:
                str_value = "None"
            elif isinstance(value, list):
                str_value = f"\n\n{AsciiDoc.bulleted_list(value)}"  # type: ignore[reportUnknownArgumentType]
            else:
                str_value = str(value)

            if field == "from":
                str_value += (
                    " ({ref}/common-options.html#date-math[Date Math format], see also <<rule-schedule, "
                    "`Additional look-back time`>>)"
                )

            values.extend([AsciiDoc.bold_kv(friendly_name, str_value), ""])

        return "\n".join(values)

    def guide_str(self) -> str:
        """Add the guide section to the rule detail page."""
        guide = convert_markdown_to_asciidoc(self.rule["note"])
        return f"{AsciiDoc.title(4, 'Investigation guide')}\n\n\n{guide}"

    def setup_str(self) -> str:
        """Add the setup section to the rule detail page."""
        setup = convert_markdown_to_asciidoc(self.rule["setup"])
        return f"{AsciiDoc.title(4, 'Setup')}\n\n\n{setup}"

    def query_str(self) -> str:
        """Add the query section to the rule detail page."""
        return f"{AsciiDoc.title(4, 'Rule query')}\n\n\n{AsciiDoc.code(self.rule['query'])}"

    def threat_mapping_str(self) -> str:
        """Add the threat mapping section to the rule detail page."""
        values = [AsciiDoc.bold_kv("Framework", "MITRE ATT&CK^TM^"), ""]

        for entry in self.rule["threat"]:
            tactic = entry["tactic"]
            entry_values = [
                AsciiDoc.bulleted("Tactic:"),
                AsciiDoc.bulleted(f"Name: {tactic['name']}", depth=2),
                AsciiDoc.bulleted(f"ID: {tactic['id']}", depth=2),
                AsciiDoc.bulleted(f"Reference URL: {tactic['reference']}", depth=2),
            ]

            techniques = entry.get("technique", [])
            for technique in techniques:
                entry_values.extend(
                    [
                        AsciiDoc.bulleted("Technique:"),
                        AsciiDoc.bulleted(f"Name: {technique['name']}", depth=2),
                        AsciiDoc.bulleted(f"ID: {technique['id']}", depth=2),
                        AsciiDoc.bulleted(f"Reference URL: {technique['reference']}", depth=2),
                    ]
                )

                subtechniques = technique.get("subtechnique", [])
                for subtechnique in subtechniques:
                    entry_values.extend(
                        [
                            AsciiDoc.bulleted("Sub-technique:"),
                            AsciiDoc.bulleted(f"Name: {subtechnique['name']}", depth=2),
                            AsciiDoc.bulleted(f"ID: {subtechnique['id']}", depth=2),
                            AsciiDoc.bulleted(f"Reference URL: {subtechnique['reference']}", depth=2),
                        ]
                    )

            values.extend(entry_values)

        return "\n".join(values)


def name_to_title(name: str) -> str:
    """Convert a rule name to tile."""
    initial = re.sub(r"[^\w]|_", r"-", name.lower().strip())
    return re.sub(r"-{2,}", "-", initial).strip("-")


def convert_markdown_to_asciidoc(text: str) -> str:
    """Convert investigation guides and setup content from markdown to asciidoc."""

    # Format the content after the stripped headers (#) to bold text with newlines.
    markdown_header_pattern = re.compile(r"^(#+)\s*(.*?)$", re.MULTILINE)
    text = re.sub(markdown_header_pattern, lambda m: f"\n*{m.group(2).strip()}*\n", text)

    # Convert Markdown links to AsciiDoc format
    markdown_link_pattern = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
    return re.sub(markdown_link_pattern, lambda m: f"{m.group(2)}[{m.group(1)}]", text)


@dataclass
class UpdateEntry:
    """A class schema for downloadable update entries."""

    update_version: str
    date: str
    new_rules: int
    updated_rules: int
    note: str
    url: str


@dataclass
class DownloadableUpdates:
    """A class for managing downloadable updates."""

    packages: list[UpdateEntry]

    @classmethod
    def load_updates(cls) -> "DownloadableUpdates":
        """Load the package."""
        prebuilt = load_etc_dump(["downloadable_updates.json"])
        packages = [UpdateEntry(**entry) for entry in prebuilt["packages"]]
        return cls(packages)

    def save_updates(self) -> None:
        """Save the package."""
        sorted_package = sorted(self.packages, key=lambda entry: Version.parse(entry.update_version), reverse=True)
        data = {"packages": [asdict(entry) for entry in sorted_package]}
        save_etc_dump(data, ["downloadable_updates.json"])

    def add_entry(self, entry: UpdateEntry, overwrite: bool = False) -> None:
        """Add an entry to the package."""
        existing_entry_index = -1
        for index, existing_entry in enumerate(self.packages):
            if existing_entry.update_version == entry.update_version:
                if not overwrite:
                    raise ValueError(f"Update version {entry.update_version} already exists.")
                existing_entry_index = index
                break

        if existing_entry_index >= 0:
            self.packages[existing_entry_index] = entry
        else:
            self.packages.append(entry)


class MDX:
    """A class for generating Markdown content."""

    @classmethod
    def bold(cls, value: str) -> str:
        """Return a bold str in Markdown."""
        return f"**{value}**"

    @classmethod
    def bold_kv(cls, key: str, value: str) -> str:
        """Return a bold key-value pair in Markdown."""
        return f"**{key}**: {value}"

    @classmethod
    def description_list(cls, value: dict[str, str], linesep: str = "\n\n") -> str:
        """Create a description list in Markdown."""
        return f"{linesep}".join(f"**{k}**:\n\n{v}" for k, v in value.items())

    @classmethod
    def bulleted(cls, value: str, depth: int = 1) -> str:
        """Create a bulleted list item with a specified depth."""
        return f"{'  ' * (depth - 1)}* {value}"

    @classmethod
    def bulleted_list(cls, values: list[str]) -> str:
        """Create a bulleted list from an iterable."""
        return "\n* " + "\n* ".join(values)

    @classmethod
    def code(cls, value: str, language: str = "js") -> str:
        """Return a code block with the specified language."""
        return f"```{language}\n{value}```"

    @classmethod
    def title(cls, depth: int, value: str) -> str:
        """Create a title with the specified depth."""
        return f"{'#' * depth} {value}"

    @classmethod
    def inline_anchor(cls, value: str) -> str:
        """Create an inline anchor with the specified value."""
        return f'<a id="{value}" />'

    @classmethod
    def table(cls, data: dict[str, Any]) -> str:
        """Create a table from a dictionary."""
        entries = [f"| {k} | {v}" for k, v in data.items()]
        table = ["|---|---|", *entries]
        return "\n".join(table)


class IntegrationSecurityDocsMDX:
    """Generate docs for prebuilt rules in Elastic documentation using MDX."""

    def __init__(  # noqa: PLR0913
        self,
        release_version: str,
        directory: Path,
        overwrite: bool = False,
        new_package: Package | None = None,
        historical_package: dict[str, Any] | None = None,
        note: str | None = "Rule Updates.",
    ) -> None:
        self.historical_package = historical_package
        self.new_package = new_package
        self.rule_changes = self.get_rule_changes()
        self.included_rules = list(
            itertools.chain(self.rule_changes["new"], self.rule_changes["updated"], self.rule_changes["deprecated"])
        )

        self.release_version_str, self.base_name, self.prebuilt_rule_base = self.parse_release(release_version)
        self.package_directory = directory / self.base_name
        self.overwrite = overwrite
        self.note = note

        if overwrite:
            shutil.rmtree(self.package_directory, ignore_errors=True)

        self.package_directory.mkdir(parents=True, exist_ok=overwrite)

    @staticmethod
    def parse_release(release_version_val: str) -> tuple[str, str, str]:
        """Parse the release version into a string, base name, and prebuilt rule base."""
        release_version = Version.parse(release_version_val)
        parts = release_version[:3]
        short_release_version = [str(n) for n in parts]  # type: ignore[reportOptionalIterable]
        release_version_str = ".".join(short_release_version)
        base_name = "-".join(short_release_version)
        prebuilt_rule_base = f"prebuilt-rule-{base_name}"

        return release_version_str, base_name, prebuilt_rule_base

    def get_rule_changes(self) -> dict[str, list[TOMLRule | DeprecatedRule]]:
        """Compare the rules from the new_package against rules in the historical_package."""

        rule_changes: dict[str, list[TOMLRule | DeprecatedRule]] = {
            "new": [],
            "updated": [],
            "deprecated": [],
        }

        historical_package: dict[str, Any] = self.historical_package or {}
        historical_rule_ids: set[str] = set(historical_package.keys())

        if self.new_package:
            # Identify new and updated rules
            for rule in self.new_package.rules:
                rule_to_api_format = rule.contents.to_api_format()

                latest_version = rule_to_api_format["version"]
                rule_id = f"{rule.id}_{latest_version}"

                if rule_id not in historical_rule_ids and latest_version == 1:
                    rule_changes["new"].append(rule)
                elif rule_id not in historical_rule_ids:
                    rule_changes["updated"].append(rule)

        # Identify deprecated rules
        # if rule is in the historical but not in the current package, its deprecated
        deprecated_rule_ids: list[str] = []
        for content in historical_package.values():
            rule_id = content["attributes"]["rule_id"]
            if self.new_package and rule_id in self.new_package.deprecated_rules.id_map:
                deprecated_rule_ids.append(rule_id)

        deprecated_rule_ids = list(set(deprecated_rule_ids))
        for rule_id in deprecated_rule_ids:
            if self.new_package:
                rule_changes["deprecated"].append(self.new_package.deprecated_rules.id_map[rule_id])

        return dict(rule_changes)

    def generate_current_rule_summary(self) -> None:
        """Generate a summary of all available current rules in the latest package."""
        slug = f"prebuilt-rules-{self.base_name}-all-available-summary.mdx"
        summary = self.package_directory / slug
        title = f"Latest rules for Stack Version ^{self.release_version_str}"

        summary_header = textwrap.dedent(f"""
        ---
        id: {slug}
        slug: /security-rules/{slug}
        title: {title}
        date: {datetime.today().strftime("%Y-%d-%m")}
        tags: ["rules", "security", "detection-rules"]
        ---

        ## {title}
        This section lists all available rules supporting latest package version {self.release_version_str}
            and greater of the Fleet integration *Prebuilt Security Detection Rules*.

        | Rule | Description | Tags | Version
        |---|---|---|---|
        """).lstrip()  # noqa: DTZ002

        rule_entries: list[str] = []

        if self.new_package:
            for rule in self.new_package.rules:
                title_name = name_to_title(rule.name)
                to_api_format = rule.contents.to_api_format()
                tags = ", ".join(to_api_format["tags"])
                rule_entries.append(
                    f"| [{title_name}](rules/{self.prebuilt_rule_base}-{name_to_title(rule.name)}.mdx) | "
                    f"{to_api_format['description']} | {tags} | "
                    f"{to_api_format['version']}"
                )

        rule_entries = sorted(rule_entries)
        rule_entries_str = "\n".join(rule_entries)

        _ = summary.write_text(summary_header + rule_entries_str)

    def generate_update_summary(self) -> None:
        """Generate a summary of all rule updates based on the latest package."""
        slug = f"prebuilt-rules-{self.base_name}-update-summary.mdx"
        summary = self.package_directory / slug
        title = "Current Available Rules"

        summary_header = textwrap.dedent(f"""
        ---
        id: {slug}
        slug: /security-rules/{slug}
        title: {title}
        date: {datetime.today().strftime("%Y-%d-%m")}
        tags: ["rules", "security", "detection-rules"]
        ---

        ## {title}
        This section lists all updates associated with version {self.release_version_str}
            of the Fleet integration *Prebuilt Security Detection Rules*.

        | Rule | Description | Status | Version
        |---|---|---|---|
        """).lstrip()  # noqa: DTZ002

        rule_entries: list[str] = []
        new_rule_id_list = [rule.id for rule in self.rule_changes["new"]]
        updated_rule_id_list = [rule.id for rule in self.rule_changes["updated"]]
        for rule in self.included_rules:
            if not rule.name:
                raise ValueError("No rule name found")
            title_name = name_to_title(rule.name)
            status = (
                "new" if rule.id in new_rule_id_list else "update" if rule.id in updated_rule_id_list else "deprecated"
            )
            to_api_format = rule.contents.to_api_format()
            rule_entries.append(
                f"| [{title_name}](rules/{self.prebuilt_rule_base}-{name_to_title(rule.name)}.mdx) | "
                f"{to_api_format['description']} | {status} | "
                f"{to_api_format['version']}"
            )

        rule_entries = sorted(rule_entries)
        rule_entries_str = "\n".join(rule_entries)

        _ = summary.write_text(summary_header + rule_entries_str)

    def generate_rule_details(self) -> None:
        """Generate a markdown file for each rule."""
        rules_dir = self.package_directory / "rules"
        rules_dir.mkdir(exist_ok=True)
        if self.new_package:
            for rule in self.new_package.rules:
                slug = f"{self.prebuilt_rule_base}-{name_to_title(rule.name)}.mdx"
                rule_detail = IntegrationRuleDetailMDX(rule.id, rule.contents.to_api_format(), {}, self.base_name)
                rule_path = rules_dir / slug
                tags = ", ".join(f'"{tag}"' for tag in rule.contents.data.tags)  # type: ignore[reportOptionalIterable]
                frontmatter = textwrap.dedent(f"""
                ---
                id: {slug}
                slug: /security-rules/{slug}
                title: {rule.name}
                date: {datetime.today().strftime("%Y-%d-%m")}
                tags: [{tags}]
                ---

                """).lstrip()  # noqa: DTZ002
                _ = rule_path.write_text(frontmatter + rule_detail.generate())

    def generate_downloadable_updates_summary(self) -> None:
        """Generate a summary of all the downloadable updates."""

        docs_url = "https://www.elastic.co/guide/en/security/current/rules-ui-management.html#update-prebuilt-rules"
        slug = "prebuilt-rules-downloadable-packages-summary.mdx"
        title = "Downloadable rule updates"
        summary = self.package_directory / slug
        today = datetime.today().strftime("%d %b %Y")  # noqa: DTZ002
        package_list = DownloadableUpdates.load_updates()
        ref = f"./prebuilt-rules-{self.base_name}-update-summary.mdx"

        # Add a new entry
        new_entry = UpdateEntry(
            update_version=self.release_version_str,
            date=today,
            new_rules=len(self.rule_changes["new"]),
            updated_rules=len(self.rule_changes["updated"]),
            note=self.note or "",
            url=ref,
        )
        package_list.add_entry(new_entry, self.overwrite)

        # Write the updated Package object back to the JSON file
        package_list.save_updates()

        # generate the summary
        summary_header = textwrap.dedent(f"""
        ---
        id: {slug}
        slug: /security-rules/{slug}
        title: {title}
        date: {datetime.today().strftime("%Y-%d-%m")}
        tags: ["rules", "security", "detection-rules"]
        ---

        ## {title}

        This section lists all updates to prebuilt detection rules, made available
            with the Prebuilt Security Detection Rules integration in Fleet.

        To update your rules to the latest versions, follow the instructions in [update-prebuilt-rules]({docs_url})


        |Update version |Date | New rules | Updated rules | Notes
        |---|---|---|---|---|
        """).lstrip()  # noqa: DTZ002

        entries: list[str] = [
            (
                f"| [{entry.update_version}]({entry.url}) | {today} |"
                f" {entry.new_rules} | {entry.updated_rules} | {entry.note}| "
            )
            for entry in sorted(
                package_list.packages,
                key=lambda entry: Version.parse(entry.update_version),
                reverse=True,
            )
        ]

        entries_str = "\n".join(entries)
        _ = summary.write_text(summary_header + entries_str)

    def generate(self) -> Path:
        """Generate the updates."""

        # generate all the rules as markdown files
        self.generate_rule_details()

        # generate the rule summary of changes within a package
        self.generate_update_summary()

        # generate the package summary that lists all downloadable packages
        self.generate_downloadable_updates_summary()

        # generate the overview that lists all current available rules
        self.generate_current_rule_summary()

        return self.package_directory


class IntegrationRuleDetailMDX:
    """Generates a rule detail page in Markdown."""

    def __init__(
        self,
        rule_id: str,
        rule: dict[str, Any],
        changelog: dict[str, dict[str, Any]],
        package_str: str,
    ) -> None:
        """Initialize with rule ID, rule details, changelog, and package string.

        >>> rule_file = "/path/to/rule.toml"
        >>> rule = RuleCollection().load_file(Path(rule_file))
        >>> rule_detail = IntegrationRuleDetailMDX(rule.id, rule.contents.to_api_format(), {}, "test")
        >>> rule_detail.generate()

        """
        self.rule_id = rule_id
        self.rule = rule
        self.changelog = changelog
        self.package = package_str
        self.rule_title = f"prebuilt-rule-{self.package}-{name_to_title(self.rule['name'])}"

        # set some defaults
        self.rule.setdefault("max_signals", 100)
        self.rule.setdefault("interval", "5m")

    def generate(self) -> str:
        """Generate the rule detail page in Markdown."""
        page = [MDX.title(1, self.rule["name"]), "", self.rule["description"], "", self.metadata_str(), ""]
        if "note" in self.rule:
            page.extend([self.guide_str(), ""])
        if "query" in self.rule:
            page.extend([self.query_str(), ""])
        if "threat" in self.rule:
            page.extend([self.threat_mapping_str(), ""])

        return "\n".join(page)

    def metadata_str(self) -> str:
        """Generate the metadata section for the rule detail page."""

        date_math_doc = "https://www.elastic.co/guide/en/elasticsearch/reference/current/common-options.html#date-math"
        loopback_doc = "https://www.elastic.co/guide/en/security/current/rules-ui-create.html#rule-schedule"
        fields = {
            "type": "Rule type",
            "index": "Rule indices",
            "severity": "Severity",
            "risk_score": "Risk score",
            "interval": "Runs every",
            "from": "Searches indices from",
            "max_signals": "Maximum alerts per execution",
            "references": "References",
            "tags": "Tags",
            "version": "Version",
            "author": "Rule authors",
            "license": "Rule license",
        }
        values: list[str] = []

        for field, friendly_name in fields.items():
            value = self.rule.get(field) or self.changelog.get(field)
            if value is None:
                str_value = "NONE"
            elif isinstance(value, list):
                str_value = MDX.bulleted_list(value)  # type: ignore[reportUnknownArgumentType]
            else:
                str_value = str(value)

            if field == "from":
                str_value += f" ([Date Math format]({date_math_doc}), [Additional look-back time]({loopback_doc}))"

            values.append(MDX.bold_kv(friendly_name, str_value))

        return "\n\n".join(values)

    def guide_str(self) -> str:
        """Generate the investigation guide section for the rule detail page."""
        return f"{MDX.title(2, 'Investigation guide')}\n\n{MDX.code(self.rule['note'], 'markdown')}"

    def query_str(self) -> str:
        """Generate the rule query section for the rule detail page."""
        return f"{MDX.title(2, 'Rule query')}\n\n{MDX.code(self.rule['query'], 'sql')}"

    def threat_mapping_str(self) -> str:
        """Generate the threat mapping section for the rule detail page."""
        values = [MDX.bold_kv("Framework", "MITRE ATT&CK^TM^")]

        for entry in self.rule["threat"]:
            tactic = entry["tactic"]
            entry_values = [
                MDX.bulleted(MDX.bold("Tactic:")),
                MDX.bulleted(f"Name: {tactic['name']}", depth=2),
                MDX.bulleted(f"ID: {tactic['id']}", depth=2),
                MDX.bulleted(f"Reference URL: {tactic['reference']}", depth=2),
            ]
            techniques = entry.get("technique", [])
            for technique in techniques:
                entry_values.extend(
                    [
                        MDX.bulleted("Technique:"),
                        MDX.bulleted(f"Name: {technique['name']}", depth=3),
                        MDX.bulleted(f"ID: {technique['id']}", depth=3),
                        MDX.bulleted(f"Reference URL: {technique['reference']}", depth=3),
                    ]
                )

                subtechniques = technique.get("subtechnique", [])
                for subtechnique in subtechniques:
                    entry_values.extend(
                        [
                            MDX.bulleted("Sub-technique:"),
                            MDX.bulleted(f"Name: {subtechnique['name']}", depth=3),
                            MDX.bulleted(f"ID: {subtechnique['id']}", depth=3),
                            MDX.bulleted(f"Reference URL: {subtechnique['reference']}", depth=4),
                        ]
                    )

            values.extend(entry_values)

        return "\n".join(values)

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Packaging and preparation for releases."""
import base64
import datetime
import hashlib
import json
import os
import shutil
import textwrap
from collections import defaultdict
from pathlib import Path
from typing import Dict, Optional, Tuple
from semver import Version

import click
import yaml

from .config import load_current_package_version, parse_rules_config
from .misc import JS_LICENSE, cached
from .navigator import NavigatorBuilder, Navigator
from .rule import TOMLRule, QueryRuleData, ThreatMapping
from .rule_loader import DeprecatedCollection, RuleCollection
from .schemas import definitions
from .utils import Ndjson, get_path, get_etc_path
from .version_lock import loaded_version_lock


RULES_CONFIG = parse_rules_config()
RELEASE_DIR = get_path("releases")
PACKAGE_FILE = str(RULES_CONFIG.packages_file)
NOTICE_FILE = get_path('NOTICE.txt')
FLEET_PKG_LOGO = get_etc_path("security-logo-color-64px.svg")


# CHANGELOG_FILE = Path(get_etc_path('rules-changelog.json'))


def filter_rule(rule: TOMLRule, config_filter: dict, exclude_fields: Optional[dict] = None) -> bool:
    """Filter a rule based off metadata and a package configuration."""
    flat_rule = rule.contents.flattened_dict()

    for key, values in config_filter.items():
        if key not in flat_rule:
            return False

        values = set([v.lower() if isinstance(v, str) else v for v in values])
        rule_value = flat_rule[key]

        if isinstance(rule_value, list):
            rule_values = {v.lower() if isinstance(v, str) else v for v in rule_value}
        else:
            rule_values = {rule_value.lower() if isinstance(rule_value, str) else rule_value}

        if len(rule_values & values) == 0:
            return False

    exclude_fields = exclude_fields or {}
    if exclude_fields:
        from .rule import get_unique_query_fields

        unique_fields = get_unique_query_fields(rule)

        for index, fields in exclude_fields.items():
            if unique_fields and (rule.contents.data.index_or_dataview == index or index == 'any'):
                if set(unique_fields) & set(fields):
                    return False

    return True


CURRENT_RELEASE_PATH = RELEASE_DIR / load_current_package_version()


class Package(object):
    """Packaging object for siem rules and releases."""

    def __init__(self, rules: RuleCollection, name: str, release: Optional[bool] = False,
                 min_version: Optional[int] = None, max_version: Optional[int] = None,
                 registry_data: Optional[dict] = None, verbose: Optional[bool] = True,
                 generate_navigator: bool = False, historical: bool = False):
        """Initialize a package."""
        self.name = name
        self.rules = rules
        self.deprecated_rules: DeprecatedCollection = rules.deprecated
        self.release = release
        self.registry_data = registry_data or {}
        self.generate_navigator = generate_navigator
        self.historical = historical

        if min_version is not None:
            self.rules = self.rules.filter(lambda r: min_version <= r.contents.saved_version)

        if max_version is not None:
            self.rules = self.rules.filter(lambda r: max_version >= r.contents.saved_version)

        assert not RULES_CONFIG.bypass_version_lock, "Packaging can not be used when version locking is bypassed."
        self.changed_ids, self.new_ids, self.removed_ids = \
            loaded_version_lock.manage_versions(self.rules, verbose=verbose, save_changes=False)

    @classmethod
    def load_configs(cls):
        """Load configs from packages.yaml."""
        return RULES_CONFIG.packages['package']

    @staticmethod
    def _package_kibana_notice_file(save_dir):
        """Convert and save notice file with package."""
        with open(NOTICE_FILE, 'rt') as f:
            notice_txt = f.read()

        with open(os.path.join(save_dir, 'notice.ts'), 'wt') as f:
            commented_notice = [f' * {line}'.rstrip() for line in notice_txt.splitlines()]
            lines = ['/* eslint-disable @kbn/eslint/require-license-header */', '', '/* @notice']
            lines = lines + commented_notice + [' */', '']
            f.write('\n'.join(lines))

    def _package_kibana_index_file(self, save_dir):
        """Convert and save index file with package."""
        sorted_rules = sorted(self.rules, key=lambda k: (k.contents.metadata.creation_date, os.path.basename(k.path)))
        comments = [
            '// Auto generated file from either:',
            '// - scripts/regen_prepackage_rules_index.sh',
            '// - detection-rules repo using CLI command build-release',
            '// Do not hand edit. Run script/command to regenerate package information instead',
        ]
        rule_imports = [f"import rule{i} from './{os.path.splitext(os.path.basename(r.path))[0] + '.json'}';"
                        for i, r in enumerate(sorted_rules, 1)]
        const_exports = ['export const rawRules = [']
        const_exports.extend(f"  rule{i}," for i, _ in enumerate(sorted_rules, 1))
        const_exports.append("];")
        const_exports.append("")

        index_ts = [JS_LICENSE, ""]
        index_ts.extend(comments)
        index_ts.append("")
        index_ts.extend(rule_imports)
        index_ts.append("")
        index_ts.extend(const_exports)

        with open(os.path.join(save_dir, 'index.ts'), 'wt') as f:
            f.write('\n'.join(index_ts))

    def save_release_files(self, directory: str, changed_rules: list, new_rules: list, removed_rules: list):
        """Release a package."""
        summary, changelog = self.generate_summary_and_changelog(changed_rules, new_rules, removed_rules)
        with open(os.path.join(directory, f'{self.name}-summary.txt'), 'w') as f:
            f.write(summary)
        with open(os.path.join(directory, f'{self.name}-changelog-entry.md'), 'w') as f:
            f.write(changelog)

        if self.generate_navigator:
            self.generate_attack_navigator(Path(directory))

        consolidated = json.loads(self.get_consolidated())
        with open(os.path.join(directory, f'{self.name}-consolidated-rules.json'), 'w') as f:
            json.dump(consolidated, f, sort_keys=True, indent=2)
        consolidated_rules = Ndjson(consolidated)
        consolidated_rules.dump(Path(directory).joinpath(f'{self.name}-consolidated-rules.ndjson'), sort_keys=True)

        self.generate_xslx(os.path.join(directory, f'{self.name}-summary.xlsx'))

        bulk_upload, rules_ndjson = self.create_bulk_index_body()
        bulk_upload.dump(Path(directory).joinpath(f'{self.name}-enriched-rules-index-uploadable.ndjson'),
                         sort_keys=True)
        rules_ndjson.dump(Path(directory).joinpath(f'{self.name}-enriched-rules-index-importable.ndjson'),
                          sort_keys=True)

    def get_consolidated(self, as_api=True):
        """Get a consolidated package of the rules in a single file."""
        full_package = []
        for rule in self.rules:
            full_package.append(rule.contents.to_api_format() if as_api else rule.contents.to_dict())

        return json.dumps(full_package, sort_keys=True)

    def save(self, verbose=True):
        """Save a package and all artifacts."""
        save_dir = RELEASE_DIR / self.name
        rules_dir = save_dir / 'rules'
        extras_dir = save_dir / 'extras'

        # remove anything that existed before
        shutil.rmtree(save_dir, ignore_errors=True)
        rules_dir.mkdir(parents=True, exist_ok=True)
        extras_dir.mkdir(parents=True, exist_ok=True)

        for rule in self.rules:
            rule.save_json(rules_dir / Path(rule.path.name).with_suffix('.json'))

        self._package_kibana_notice_file(rules_dir)
        self._package_kibana_index_file(rules_dir)

        if self.release:
            self._generate_registry_package(save_dir)
            self.save_release_files(extras_dir, self.changed_ids, self.new_ids, self.removed_ids)

            # zip all rules only and place in extras
            shutil.make_archive(extras_dir / self.name, 'zip', root_dir=rules_dir.parent, base_dir=rules_dir.name)

            # zip everything and place in release root
            shutil.make_archive(
                save_dir / f"{self.name}-all", "zip", root_dir=extras_dir.parent, base_dir=extras_dir.name
            )

        if verbose:
            click.echo(f'Package saved to: {save_dir}')

    def export(self, outfile, downgrade_version=None, verbose=True, skip_unsupported=False):
        """Export rules into a consolidated ndjson file."""
        from .main import _export_rules

        _export_rules(self.rules, outfile=outfile, downgrade_version=downgrade_version, verbose=verbose,
                      skip_unsupported=skip_unsupported)

    def get_package_hash(self, as_api=True, verbose=True):
        """Get hash of package contents."""
        contents = base64.b64encode(self.get_consolidated(as_api=as_api).encode('utf-8'))
        sha256 = hashlib.sha256(contents).hexdigest()

        if verbose:
            click.echo('- sha256: {}'.format(sha256))

        return sha256

    @classmethod
    def from_config(cls, rule_collection: Optional[RuleCollection] = None, config: Optional[dict] = None,
                    verbose: Optional[bool] = False, historical: Optional[bool] = True) -> 'Package':
        """Load a rules package given a config."""
        all_rules = rule_collection or RuleCollection.default()
        config = config or {}
        exclude_fields = config.pop('exclude_fields', {})
        # deprecated rules are now embedded in the RuleCollection.deprecated - this is left here for backwards compat
        config.pop('log_deprecated', False)
        rule_filter = config.pop('filter', {})

        rules = all_rules.filter(lambda r: filter_rule(r, rule_filter, exclude_fields))

        # add back in deprecated fields
        rules.deprecated = all_rules.deprecated

        if verbose:
            click.echo(f' - {len(all_rules) - len(rules)} rules excluded from package')

        package = cls(rules, verbose=verbose, historical=historical, **config)

        return package

    def generate_summary_and_changelog(self, changed_rule_ids, new_rule_ids, removed_rules):
        """Generate stats on package."""

        summary = {
            'changed': defaultdict(list),
            'added': defaultdict(list),
            'removed': defaultdict(list),
            'unchanged': defaultdict(list)
        }
        changelog = {
            'changed': defaultdict(list),
            'added': defaultdict(list),
            'removed': defaultdict(list),
            'unchanged': defaultdict(list)
        }

        # Build an index map first
        longest_name = 0
        indexes = set()
        for rule in self.rules:
            longest_name = max(longest_name, len(rule.name))
            index_list = getattr(rule.contents.data, "index", [])
            if index_list:
                indexes.update(index_list)

        index_map = {index: str(i) for i, index in enumerate(sorted(indexes))}

        def get_summary_rule_info(r: TOMLRule):
            r = r.contents
            rule_str = f'{r.name:<{longest_name}} (v:{r.autobumped_version} t:{r.data.type}'
            if isinstance(rule.contents.data, QueryRuleData):
                index = rule.contents.data.get("index") or []
                rule_str += f'-{r.data.language}'
                rule_str += f'(indexes:{"".join(index_map[idx] for idx in index) or "none"}'

            return rule_str

        def get_markdown_rule_info(r: TOMLRule, sd):
            # lookup the rule in the GitHub tag v{major.minor.patch}
            data = r.contents.data
            rules_dir_link = f'https://github.com/elastic/detection-rules/tree/v{self.name}/rules/{sd}/'
            rule_type = data.language if isinstance(data, QueryRuleData) else data.type
            return f'`{r.id}` **[{r.name}]({rules_dir_link + os.path.basename(str(r.path))})** (_{rule_type}_)'

        for rule in self.rules:
            sub_dir = os.path.basename(os.path.dirname(rule.path))

            if rule.id in changed_rule_ids:
                summary['changed'][sub_dir].append(get_summary_rule_info(rule))
                changelog['changed'][sub_dir].append(get_markdown_rule_info(rule, sub_dir))
            elif rule.id in new_rule_ids:
                summary['added'][sub_dir].append(get_summary_rule_info(rule))
                changelog['added'][sub_dir].append(get_markdown_rule_info(rule, sub_dir))
            else:
                summary['unchanged'][sub_dir].append(get_summary_rule_info(rule))
                changelog['unchanged'][sub_dir].append(get_markdown_rule_info(rule, sub_dir))

        for rule in self.deprecated_rules:
            sub_dir = os.path.basename(os.path.dirname(rule.path))

            if rule.id in removed_rules:
                summary['removed'][sub_dir].append(rule.name)
                changelog['removed'][sub_dir].append(rule.name)

        def format_summary_rule_str(rule_dict):
            str_fmt = ''
            for sd, rules in sorted(rule_dict.items(), key=lambda x: x[0]):
                str_fmt += f'\n{sd} ({len(rules)})\n'
                str_fmt += '\n'.join(' - ' + s for s in sorted(rules))
            return str_fmt or '\nNone'

        def format_changelog_rule_str(rule_dict):
            str_fmt = ''
            for sd, rules in sorted(rule_dict.items(), key=lambda x: x[0]):
                str_fmt += f'\n- **{sd}** ({len(rules)})\n'
                str_fmt += '\n'.join('   - ' + s for s in sorted(rules))
            return str_fmt or '\nNone'

        def rule_count(rule_dict):
            count = 0
            for _, rules in rule_dict.items():
                count += len(rules)
            return count

        today = str(datetime.date.today())
        summary_fmt = [f'{sf.capitalize()} ({rule_count(summary[sf])}): \n{format_summary_rule_str(summary[sf])}\n'
                       for sf in ('added', 'changed', 'removed', 'unchanged') if summary[sf]]

        change_fmt = [f'{sf.capitalize()} ({rule_count(changelog[sf])}): \n{format_changelog_rule_str(changelog[sf])}\n'
                      for sf in ('added', 'changed', 'removed') if changelog[sf]]

        summary_str = '\n'.join([
            f'Version {self.name}',
            f'Generated: {today}',
            f'Total Rules: {len(self.rules)}',
            f'Package Hash: {self.get_package_hash(verbose=False)}',
            '---',
            '(v: version, t: rule_type-language)',
            'Index Map:\n{}'.format("\n".join(f"  {v}: {k}" for k, v in index_map.items())),
            '',
            'Rules',
            *summary_fmt
        ])

        changelog_str = '\n'.join([
            f'# Version {self.name}',
            f'_Released {today}_',
            '',
            '### Rules',
            *change_fmt,
            '',
            '### CLI'
        ])

        return summary_str, changelog_str

    def generate_attack_navigator(self, path: Path) -> Dict[Path, Navigator]:
        """Generate ATT&CK navigator layer files."""
        save_dir = path / 'navigator_layers'
        save_dir.mkdir()
        lb = NavigatorBuilder(self.rules.rules)
        return lb.save_all(save_dir, verbose=False)

    def generate_xslx(self, path):
        """Generate a detailed breakdown of a package in an excel file."""
        from .docs import PackageDocument

        doc = PackageDocument(path, self)
        doc.populate()
        doc.close()

    def _generate_registry_package(self, save_dir):
        """Generate the artifact for the oob package-storage."""
        from .schemas.registry_package import (RegistryPackageManifestV1,
                                               RegistryPackageManifestV3)

        # 8.12.0+ we use elastic package v3
        stack_version = Version.parse(self.name, optional_minor_and_patch=True)
        if stack_version >= Version.parse('8.12.0'):
            manifest = RegistryPackageManifestV3.from_dict(self.registry_data)
        else:
            manifest = RegistryPackageManifestV1.from_dict(self.registry_data)

        package_dir = Path(save_dir) / 'fleet' / manifest.version
        docs_dir = package_dir / 'docs'
        rules_dir = package_dir / 'kibana' / definitions.ASSET_TYPE

        docs_dir.mkdir(parents=True)
        rules_dir.mkdir(parents=True)

        manifest_file = package_dir / 'manifest.yml'
        readme_file = docs_dir / 'README.md'
        notice_file = package_dir / 'NOTICE.txt'
        logo_file = package_dir / 'img' / 'security-logo-color-64px.svg'

        manifest_file.write_text(yaml.safe_dump(manifest.to_dict()))

        logo_file.parent.mkdir(parents=True)
        shutil.copyfile(FLEET_PKG_LOGO, logo_file)
        # shutil.copyfile(CHANGELOG_FILE, str(rules_dir.joinpath('CHANGELOG.json')))

        for rule in self.rules:
            asset = rule.get_asset()
            # if this package includes historical rules the IDs need to be changed
            # asset['id] and the file name needs to resemble RULEID_VERSION instead of RULEID
            asset_id = f"{asset['attributes']['rule_id']}_{asset['attributes']['version']}"
            asset["id"] = asset_id
            asset_path = rules_dir / f'{asset_id}.json'

            asset_path.write_text(json.dumps(asset, indent=4, sort_keys=True), encoding="utf-8")

        notice_contents = NOTICE_FILE.read_text()
        readme_text = textwrap.dedent("""
        # Prebuilt Security Detection Rules

        The detection rules package stores the prebuilt security rules for the Elastic Security [detection engine](https://www.elastic.co/guide/en/security/7.13/detection-engine-overview.html).

        To download or update the rules, click **Settings** > **Install Prebuilt Security Detection Rules assets**.
        Then [import](https://www.elastic.co/guide/en/security/current/rules-ui-management.html#load-prebuilt-rules)
        the rules into the Detection engine.

        ## License Notice

        """).lstrip()  # noqa: E501

        # notice only needs to be appended to the README for 7.13.x
        # in 7.14+ there's a separate modal to display this
        if self.name == "7.13":
            textwrap.indent(notice_contents, prefix="    ")

        readme_file.write_text(readme_text)
        notice_file.write_text(notice_contents)

    def create_bulk_index_body(self) -> Tuple[Ndjson, Ndjson]:
        """Create a body to bulk index into a stack."""
        package_hash = self.get_package_hash(verbose=False)
        now = datetime.datetime.isoformat(datetime.datetime.utcnow())
        create = {'create': {'_index': f'rules-repo-{self.name}-{package_hash}'}}

        # first doc is summary stats
        summary_doc = {
            'group_hash': package_hash,
            'package_version': self.name,
            'rule_count': len(self.rules),
            'rule_ids': [],
            'rule_names': [],
            'rule_hashes': [],
            'source': 'repo',
            'details': {'datetime_uploaded': now}
        }
        bulk_upload_docs = Ndjson([create, summary_doc])
        importable_rules_docs = Ndjson()

        for rule in self.rules:
            summary_doc['rule_ids'].append(rule.id)
            summary_doc['rule_names'].append(rule.name)
            summary_doc['rule_hashes'].append(rule.contents.get_hash())

            if rule.id in self.new_ids:
                status = 'new'
            elif rule.id in self.changed_ids:
                status = 'modified'
            else:
                status = 'unmodified'

            bulk_upload_docs.append(create)

            relative_path = str(rule.get_base_rule_dir())

            if relative_path is None:
                raise ValueError(f"Could not find a valid relative path for the rule: {rule.id}")

            rule_doc = dict(hash=rule.contents.get_hash(),
                            source='repo',
                            datetime_uploaded=now,
                            status=status,
                            package_version=self.name,
                            flat_mitre=ThreatMapping.flatten(rule.contents.data.threat).to_dict(),
                            relative_path=relative_path)
            rule_doc.update(**rule.contents.to_api_format())
            bulk_upload_docs.append(rule_doc)
            importable_rules_docs.append(rule_doc)

        return bulk_upload_docs, importable_rules_docs

    @staticmethod
    def add_historical_rules(historical_rules: Dict[str, dict], manifest_version: str) -> list:
        """Adds historical rules to existing build package."""
        rules_dir = CURRENT_RELEASE_PATH / 'fleet' / manifest_version / 'kibana' / 'security_rule'

        # iterates over historical rules from previous package and writes them to disk
        for _, historical_rule_contents in historical_rules.items():
            rule_id = historical_rule_contents["attributes"]["rule_id"]
            historical_rule_version = historical_rule_contents['attributes']['version']

            # checks if the rule exists in the current package first
            current_rule_path = list(rules_dir.glob(f"{rule_id}*.json"))
            if not current_rule_path:
                continue

            # load the current rule from disk
            current_rule_path = current_rule_path[0]
            current_rule_json = json.load(current_rule_path.open(encoding="UTF-8"))
            current_rule_version = current_rule_json['attributes']['version']

            # if the historical rule version and current rules version differ, write
            # the historical rule to disk
            if historical_rule_version != current_rule_version:
                historical_rule_path = rules_dir / f"{rule_id}_{historical_rule_version}.json"
                with historical_rule_path.open("w", encoding="UTF-8") as file:
                    json.dump(historical_rule_contents, file)


@cached
def current_stack_version() -> str:
    return Package.load_configs()['name']

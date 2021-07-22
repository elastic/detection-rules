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
from typing import List, Optional, Tuple

import click
import yaml

from .misc import JS_LICENSE, cached
from .rule import TOMLRule, QueryRuleData, ThreatMapping
from .rule import downgrade_contents_from_rule
from .rule_loader import RuleCollection, DEFAULT_RULES_DIR
from .schemas import definitions
from .utils import Ndjson, dict_hash, get_path, get_etc_path, load_etc_dump, save_etc_dump

RELEASE_DIR = get_path("releases")
PACKAGE_FILE = get_etc_path('packages.yml')
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
    for index, fields in exclude_fields.items():
        if rule.contents.data.unique_fields and (rule.contents.data.index == index or index == 'any'):
            if set(rule.contents.data.unique_fields) & set(fields):
                return False

    return True


@cached
def load_current_package_version() -> str:
    """Load the current package version from config file."""
    return load_etc_dump('packages.yml')['package']['name']


@cached
def load_versions(current_versions: dict = None):
    """Load the versions file."""
    return current_versions or load_etc_dump('version.lock.json')


def manage_versions(rules: List[TOMLRule], current_versions: dict = None,
                    exclude_version_update=False, add_new=True, save_changes=False,
                    verbose=True) -> (List[str], List[str], List[str]):
    """Update the contents of the version.lock file and optionally save changes."""
    current_versions = load_versions(current_versions)
    versions_hash = dict_hash(current_versions)
    rule_deprecations = load_etc_dump('deprecated_rules.json')

    echo = click.echo if verbose else (lambda x: None)

    already_deprecated = set(rule_deprecations)
    deprecated_rules = set(rule.id for rule in rules if rule.contents.metadata.maturity == "deprecated")
    new_rules = set(rule.id for rule in rules if rule.contents.latest_version is None) - deprecated_rules
    changed_rules = set(rule.id for rule in rules if rule.contents.is_dirty) - deprecated_rules

    # manage deprecated rules
    newly_deprecated = deprecated_rules - already_deprecated

    if not (new_rules or changed_rules or newly_deprecated):
        return list(changed_rules), list(new_rules), list(newly_deprecated)

    echo('Rule changes detected!')

    if not save_changes:
        echo('run `build-release --update-version-lock` to update version.lock.json and deprecated_rules.json')
        return list(changed_rules), list(new_rules), list(newly_deprecated)

    for rule in rules:
        contents = rule.contents.lock_info(bump=not exclude_version_update)

        if rule.contents.metadata.maturity == "production":
            current_versions[rule.id] = contents

        elif rule.id in newly_deprecated:
            current_versions[rule.id] = contents
            rule_deprecations[rule.id] = {
                "rule_name": rule.name,
                "stack_version": current_stack_version,
                "deprecation_date": rule.contents.metadata.deprecation_date
            }

    new_hash = dict_hash(current_versions)

    if versions_hash != new_hash:
        save_etc_dump(current_versions, 'version.lock.json')
        echo('Updated version.lock.json file')

    if newly_deprecated:
        save_etc_dump(rule_deprecations, 'deprecated_rules.json')
        echo('Updated deprecated_rules.json file')

    echo(f' - {len(changed_rules)} changed rules')
    echo(f' - {len(new_rules)} new rules')
    echo(f' - {len(newly_deprecated)} newly deprecated rules')

    return changed_rules, list(new_rules), newly_deprecated


class Package(object):
    """Packaging object for siem rules and releases."""

    def __init__(self, rules: List[TOMLRule], name: str, deprecated_rules: Optional[List[TOMLRule]] = None,
                 release: Optional[bool] = False, current_versions: Optional[dict] = None,
                 min_version: Optional[int] = None, max_version: Optional[int] = None,
                 update_version_lock: Optional[bool] = False, registry_data: Optional[dict] = None,
                 verbose: Optional[bool] = True):
        """Initialize a package."""
        self.name = name
        self.rules = rules
        self.deprecated_rules: List[TOMLRule] = deprecated_rules or []
        self.release = release
        self.registry_data = registry_data or {}

        self.changed_rule_ids, self.new_rules_ids, self.removed_rule_ids = self._add_versions(current_versions,
                                                                                              update_version_lock,
                                                                                              verbose=verbose)

        if min_version or max_version:
            self.rules = [r for r in self.rules
                          if (min_version or 0) <= r.contents['version'] <= (max_version or r.contents['version'])]

    def _add_versions(self, current_versions, update_versions_lock=False, verbose=True):
        """Add versions to rules at load time."""
        return manage_versions(self.rules, current_versions=current_versions,
                               save_changes=update_versions_lock, verbose=verbose)

    @classmethod
    def load_configs(cls):
        """Load configs from packages.yml."""
        return load_etc_dump(PACKAGE_FILE)['package']

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

    def save_release_files(self, directory, changed_rules, new_rules, removed_rules):
        """Release a package."""
        summary, changelog = self.generate_summary_and_changelog(changed_rules, new_rules, removed_rules)
        with open(os.path.join(directory, f'{self.name}-summary.txt'), 'w') as f:
            f.write(summary)
        with open(os.path.join(directory, f'{self.name}-changelog-entry.md'), 'w') as f:
            f.write(changelog)

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
        save_dir = os.path.join(RELEASE_DIR, self.name)
        rules_dir = os.path.join(save_dir, 'rules')
        extras_dir = os.path.join(save_dir, 'extras')

        # remove anything that existed before
        shutil.rmtree(save_dir, ignore_errors=True)
        os.makedirs(rules_dir, exist_ok=True)
        os.makedirs(extras_dir, exist_ok=True)

        for rule in self.rules:
            rule.save_json(Path(rules_dir).joinpath(rule.path.name).with_suffix('.json'))

        self._package_kibana_notice_file(rules_dir)
        self._package_kibana_index_file(rules_dir)

        if self.release:
            self._generate_registry_package(save_dir)
            self.save_release_files(extras_dir, self.changed_rule_ids, self.new_rules_ids, self.removed_rule_ids)

            # zip all rules only and place in extras
            shutil.make_archive(os.path.join(extras_dir, self.name), 'zip', root_dir=os.path.dirname(rules_dir),
                                base_dir=os.path.basename(rules_dir))

            # zip everything and place in release root
            shutil.make_archive(os.path.join(save_dir, '{}-all'.format(self.name)), 'zip',
                                root_dir=os.path.dirname(extras_dir), base_dir=os.path.basename(extras_dir))

        if verbose:
            click.echo('Package saved to: {}'.format(save_dir))

    def export(self, outfile, downgrade_version=None, verbose=True, skip_unsupported=False):
        """Export rules into a consolidated ndjson file."""
        outfile = Path(outfile).with_suffix('.ndjson')
        unsupported = []

        if downgrade_version:
            if skip_unsupported:
                output_lines = []

                for rule in self.rules:
                    try:
                        output_lines.append(json.dumps(downgrade_contents_from_rule(rule, downgrade_version),
                                                       sort_keys=True))
                    except ValueError as e:
                        unsupported.append(f'{e}: {rule.id} - {rule.name}')
                        continue

            else:
                output_lines = [json.dumps(downgrade_contents_from_rule(r, downgrade_version), sort_keys=True)
                                for r in self.rules]
        else:
            output_lines = [json.dumps(r.contents.data.to_dict(), sort_keys=True) for r in self.rules]

        outfile.write_text('\n'.join(output_lines) + '\n')

        if verbose:
            click.echo(f'Exported {len(self.rules) - len(unsupported)} rules into {outfile}')

            if skip_unsupported and unsupported:
                unsupported_str = '\n- '.join(unsupported)
                click.echo(f'Skipped {len(unsupported)} unsupported rules: \n- {unsupported_str}')

    def get_package_hash(self, as_api=True, verbose=True):
        """Get hash of package contents."""
        contents = base64.b64encode(self.get_consolidated(as_api=as_api).encode('utf-8'))
        sha256 = hashlib.sha256(contents).hexdigest()

        if verbose:
            click.echo('- sha256: {}'.format(sha256))

        return sha256

    @classmethod
    def from_config(cls, config: dict = None, update_version_lock: bool = False, verbose: bool = False) -> 'Package':
        """Load a rules package given a config."""
        all_rules = RuleCollection.default()
        config = config or {}
        exclude_fields = config.pop('exclude_fields', {})
        log_deprecated = config.pop('log_deprecated', False)
        rule_filter = config.pop('filter', {})
        deprecated_rules = []

        if log_deprecated:
            deprecated_rules = [r for r in all_rules if r.contents.metadata.maturity == 'deprecated']

        rules = all_rules.filter(lambda r: filter_rule(r, rule_filter, exclude_fields))

        if verbose:
            click.echo(f' - {len(all_rules) - len(rules)} rules excluded from package')

        package = cls(rules, deprecated_rules=deprecated_rules, update_version_lock=update_version_lock,
                      verbose=verbose, **config)

        return package

    def generate_summary_and_changelog(self, changed_rule_ids, new_rule_ids, removed_rules):
        """Generate stats on package."""
        from string import ascii_lowercase, ascii_uppercase

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

        # build an index map first
        longest_name = 0
        indexes = set()
        for rule in self.rules:
            longest_name = max(longest_name, len(rule.name))
            index_list = getattr(rule.contents.data, "index", [])
            if index_list:
                indexes.update(index_list)

        letters = ascii_uppercase + ascii_lowercase
        index_map = {index: letters[i] for i, index in enumerate(sorted(indexes))}

        def get_summary_rule_info(r: TOMLRule):
            r = r.contents
            rule_str = f'{r.name:<{longest_name}} (v:{r.autobumped_version} t:{r.data.type}'
            if isinstance(rule.contents.data, QueryRuleData):
                rule_str += f'-{r.data.language}'
                rule_str += f'(indexes:{"".join(index_map[idx] for idx in rule.contents.data.index) or "none"}'

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

    def generate_xslx(self, path):
        """Generate a detailed breakdown of a package in an excel file."""
        from .docs import PackageDocument

        doc = PackageDocument(path, self)
        doc.populate()
        doc.close()

    def _generate_registry_package(self, save_dir):
        """Generate the artifact for the oob package-storage."""
        from .schemas.registry_package import RegistryPackageManifest

        manifest = RegistryPackageManifest.from_dict(self.registry_data)

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
            asset_path = rules_dir / f'{rule.id}.json'
            asset_path.write_text(json.dumps(rule.get_asset(), indent=4, sort_keys=True), encoding="utf-8")

        notice_contents = Path(NOTICE_FILE).read_text()
        readme_text = textwrap.dedent("""
        # Prebuilt Security Detection Rules

        The detection rules package stores the prebuilt security rules for the Elastic Security [detection engine](https://www.elastic.co/guide/en/security/7.13/detection-engine-overview.html).

        To download or update the rules, click **Settings** > **Install Prebuilt Security Detection Rules assets**.
        Then [import](https://www.elastic.co/guide/en/security/master/rules-ui-management.html#load-prebuilt-rules)
        the rules into the Detection engine.

        ## License Notice

        """).lstrip()  # noqa: E501

        # notice only needs to be appended to the README for 7.13.x
        # in 7.14+ there's a separate modal to display this
        if self.name == "7.13":
            textwrap.indent(notice_contents, prefix="    ")

        readme_file.write_text(readme_text)
        notice_file.write_text(notice_contents)

    def bump_versions(self, save_changes=False, current_versions=None):
        """Bump the versions of all production rules included in a release and optionally save changes."""
        return manage_versions(self.rules, current_versions=current_versions, save_changes=save_changes)

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
            summary_doc['rule_hashes'].append(rule.contents.sha256())

            if rule.id in self.new_rules_ids:
                status = 'new'
            elif rule.id in self.changed_rule_ids:
                status = 'modified'
            else:
                status = 'unmodified'

            bulk_upload_docs.append(create)
            rule_doc = dict(hash=rule.contents.sha256(),
                            source='repo',
                            datetime_uploaded=now,
                            status=status,
                            package_version=self.name,
                            flat_mitre=ThreatMapping.flatten(rule.contents.data.threat).to_dict(),
                            relative_path=str(rule.path.resolve().relative_to(DEFAULT_RULES_DIR)))
            bulk_upload_docs.append(rule_doc)
            importable_rules_docs.append(rule_doc)

        return bulk_upload_docs, importable_rules_docs


@cached
def current_stack_version() -> str:
    return Package.load_configs()['name']

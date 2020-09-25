# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Packaging and preparation for releases."""
import base64
import datetime
import hashlib
import json
import os
import shutil
from collections import defaultdict, OrderedDict

import click

from . import rule_loader
from .misc import JS_LICENSE
from .rule import Rule  # noqa: F401
from .utils import get_path, get_etc_path

RELEASE_DIR = get_path("releases")
PACKAGE_FILE = get_etc_path('packages.yml')
RULE_VERSIONS = get_etc_path('version.lock.json')
RULE_DEPRECATIONS = get_etc_path('deprecated_rules.json')
NOTICE_FILE = get_path('NOTICE.txt')


def filter_rule(rule: Rule, config_filter: dict, exclude_fields: dict) -> bool:
    """Filter a rule based off metadata and a package configuration."""
    flat_rule = rule.flattened_contents
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

    for index, fields in exclude_fields.items():
        if rule.unique_fields and (rule.contents['index'] == index or index == 'any'):
            if set(rule.unique_fields) & set(fields):
                return False

    return True


def manage_versions(rules: list, deprecated_rules: list = None, current_versions: dict = None,
                    exclude_version_update=False, add_new=True, save_changes=False, verbose=True) -> (list, list, list):
    """Update the contents of the version.lock file and optionally save changes."""
    new_rules = {}
    changed_rules = []

    if current_versions is None:
        with open(RULE_VERSIONS, 'r') as f:
            current_versions = json.load(f)

    for rule in rules:
        # it is a new rule, so add it if specified, and add an initial version to the rule
        if rule.id not in current_versions:
            new_rules[rule.id] = {'rule_name': rule.name, 'version': 1, 'sha256': rule.get_hash()}
            rule.contents['version'] = 1
        else:
            version_lock_info = current_versions.get(rule.id)
            version = version_lock_info['version']
            rule_hash = rule.get_hash()

            # if it has been updated, then we need to bump the version info and optionally save the changes later
            if rule_hash != version_lock_info['sha256']:
                rule.contents['version'] = version + 1

                if not exclude_version_update:
                    version_lock_info['version'] = rule.contents['version']

                version_lock_info.update(sha256=rule_hash, rule_name=rule.name)
                changed_rules.append(rule.id)
            else:
                rule.contents['version'] = version

    # manage deprecated rules
    newly_deprecated = []

    if deprecated_rules:
        with open(RULE_DEPRECATIONS, 'r') as f:
            rule_deprecations = json.load(f)

        deprecation_date = str(datetime.date.today())

        for rule in deprecated_rules:
            if rule.id not in rule_deprecations:
                rule_deprecations[rule.id] = {
                    'rule_name': rule.name,
                    'deprecation_date': deprecation_date
                }
                newly_deprecated.append(rule.id)

    # update the document with the new rules
    if new_rules or changed_rules or newly_deprecated:
        if verbose:
            click.echo('Rule hash changes detected!')

        if save_changes:
            current_versions.update(new_rules if add_new else {})
            current_versions = OrderedDict(sorted(current_versions.items(), key=lambda x: x[1]['rule_name']))

            with open(RULE_VERSIONS, 'w') as f:
                json.dump(current_versions, f, indent=2, sort_keys=True)

            if verbose:
                click.echo('Updated version.lock.json file')

            if newly_deprecated:
                with open(RULE_DEPRECATIONS, 'w') as f:
                    json.dump(sorted(OrderedDict(rule_deprecations)), f, indent=2, sort_keys=True)

                if verbose:
                    click.echo('Updated deprecated_rules.json file')
        else:
            if verbose:
                click.echo('run `build-release --update-version-lock` to update the version.lock.json and '
                           'deprecated_rules.json files')

        if verbose:
            if changed_rules:
                click.echo(' - {} changed rule version(s)'.format(len(changed_rules)))
            if new_rules:
                click.echo(' - {} new rule version addition(s)'.format(len(new_rules)))
            if newly_deprecated:
                click.echo(f' - {len(newly_deprecated)} newly deprecated rules')

    return changed_rules, new_rules.keys(), newly_deprecated


class Package(object):
    """Packaging object for siem rules and releases."""

    def __init__(self, rules, name, deprecated_rules=None, release=False, current_versions=None, min_version=None,
                 max_version=None, update_version_lock=False):
        """Initialize a package."""
        self.rules = [r.copy() for r in rules]  # type: list[Rule]
        self.name = name
        self.deprecated_rules = [r.copy() for r in deprecated_rules or []]  # type: list[Rule]
        self.release = release

        self.changed_rules, self.new_rules, self.removed_rules = self._add_versions(current_versions,
                                                                                    update_version_lock)

        if min_version or max_version:
            self.rules = [r for r in self.rules
                          if (min_version or 0) <= r.contents['version'] <= (max_version or r.contents['version'])]

    def _add_versions(self, current_versions, update_versions_lock=False):
        """Add versions to rules at load time."""
        return manage_versions(self.rules, deprecated_rules=self.deprecated_rules, current_versions=current_versions,
                               save_changes=update_versions_lock)

    @staticmethod
    def _package_notice_file(save_dir):
        """Convert and save notice file with package."""
        with open(NOTICE_FILE, 'rt') as f:
            notice_txt = f.read()

        with open(os.path.join(save_dir, 'notice.ts'), 'wt') as f:
            commented_notice = [f' * {line}'.rstrip() for line in notice_txt.splitlines()]
            lines = ['/* eslint-disable @kbn/eslint/require-license-header */', '', '/* @notice']
            lines = lines + commented_notice + [' */', '']
            f.write('\n'.join(lines))

    def _package_index_file(self, save_dir):
        """Convert and save index file with package."""
        sorted_rules = sorted(self.rules, key=lambda k: (k.metadata['creation_date'], os.path.basename(k.path)))
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
        with open(os.path.join(directory, f'{self.name}-summary.txt'), 'w') as f:
            f.write(self.generate_summary(changed_rules, new_rules, removed_rules))
        with open(os.path.join(directory, f'{self.name}-consolidated.json'), 'w') as f:
            json.dump(json.loads(self.get_consolidated()), f, sort_keys=True, indent=2)
        self.generate_xslx(os.path.join(directory, f'{self.name}-summary.xlsx'))

    def get_consolidated(self, as_api=True):
        """Get a consolidated package of the rules in a single file."""
        full_package = []
        for rule in self.rules:
            full_package.append(rule.contents if as_api else rule.rule_format())

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
            rule.save(new_path=os.path.join(rules_dir, os.path.basename(rule.path)))

        self._package_notice_file(rules_dir)
        self._package_index_file(rules_dir)

        if self.release:
            self.save_release_files(extras_dir, self.changed_rules, self.new_rules, self.removed_rules)

            # zip all rules only and place in extras
            shutil.make_archive(os.path.join(extras_dir, self.name), 'zip', root_dir=os.path.dirname(rules_dir),
                                base_dir=os.path.basename(rules_dir))

            # zip everything and place in release root
            shutil.make_archive(os.path.join(save_dir, '{}-all'.format(self.name)), 'zip',
                                root_dir=os.path.dirname(extras_dir), base_dir=os.path.basename(extras_dir))

        if verbose:
            click.echo('Package saved to: {}'.format(save_dir))

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
        all_rules = rule_loader.load_rules(verbose=False).values()
        config = config or {}
        exclude_fields = config.pop('exclude_fields', {})
        log_deprecated = config.pop('log_deprecated', False)
        rule_filter = config.pop('filter', {})

        deprecated_rules = [r for r in all_rules if r.metadata['maturity'] == 'deprecated'] if log_deprecated else []
        rules = list(filter(lambda rule: filter_rule(rule, rule_filter, exclude_fields), all_rules))

        if verbose:
            click.echo(f' - {len(all_rules) - len(rules)} rules excluded from package')

        update = config.pop('update', {})
        package = cls(rules, deprecated_rules=deprecated_rules, update_version_lock=update_version_lock, **config)

        # Allow for some fields to be overwritten
        if update.get('data', {}):
            for rule in package.rules:
                for sub_dict, values in update.items():
                    rule.contents[sub_dict].update(values)

        return package

    def generate_summary(self, changed_rules, new_rules, removed_rules):
        """Generate stats on package."""
        from string import ascii_lowercase, ascii_uppercase

        changed = defaultdict(list)
        new = defaultdict(list)
        removed = defaultdict(list)
        unchanged = defaultdict(list)

        # build an index map first
        indexes = set()
        for rule in self.rules:
            index_list = rule.contents.get('index')
            if index_list:
                indexes.update(index_list)

        letters = ascii_uppercase + ascii_lowercase
        index_map = {index: letters[i] for i, index in enumerate(sorted(indexes))}

        def get_rule_info(r):
            rule_str = f'{r.name} | (v:{r.contents.get("version")} t:{r.type}'
            rule_str += f'-{r.contents["language"]})' if r.contents.get('language') else ')'
            rule_str += f'(indexes:{"".join(index_map[i] for i in r.contents.get("index"))})' \
                if r.contents.get('index') else ''
            return rule_str

        for rule in self.rules:
            sub_dir = os.path.basename(os.path.dirname(rule.path))

            if rule.id in changed_rules:
                changed[sub_dir].append(get_rule_info(rule))
            elif rule.id in new_rules:
                new[sub_dir].append(get_rule_info(rule))
            else:
                unchanged[sub_dir].append(get_rule_info(rule))

        for rule in self.deprecated_rules:
            sub_dir = os.path.basename(os.path.dirname(rule.path))

            if rule.id in removed_rules:
                removed[sub_dir].append(rule.name)

        date = f'Generated: {datetime.date.today()}'
        total = f'Total Rules: {len(self.rules)}'
        sha256 = f'Package Hash: {self.get_package_hash(verbose=False)}'
        indexes = 'Index Map:\n{}'.format("\n".join(f"  {v}: {k}" for k, v in index_map.items()))

        def format_rule_str(rule_dict):
            str_fmt = ''
            for sd, rules in sorted(rule_dict.items(), key=lambda x: x[0]):
                str_fmt += f'\n{sd.upper()} ({len(rules)})\n'
                str_fmt += '\n'.join(' - ' + s for s in sorted(rules))
            return str_fmt or '\nNone'

        def rule_count(rule_dict):
            count = 0
            for _, rules in rule_dict.items():
                count += len(rules)
            return count

        new_rules = f'Rules Added ({rule_count(new)}): \n{format_rule_str(new)}\n'
        modified_rules = f'Rules Changed ({rule_count(changed)}): \n{format_rule_str(changed)}\n'
        deleted_rules = f'Rules Removed ({rule_count(removed)}): \n{format_rule_str(removed)}\n'
        unchanged_rules = f'Unchanged Rules ({rule_count(unchanged)}): \n{format_rule_str(unchanged)}\n'

        return '\n'.join([
            date,
            total,
            sha256,
            '---',
            '(v: version, t: rule_type-language)',
            indexes,
            '',
            new_rules,
            modified_rules,
            deleted_rules,
            unchanged_rules
        ])

    def generate_xslx(self, path):
        """Generate a detailed breakdown of a package in an excel file."""
        from .docs import PackageDocument

        doc = PackageDocument(path, self)
        doc.populate()
        doc.close()

    def generate_changelog_entry(self):
        """Generate a changelog entry."""

    def generate_json_visualization(self):
        """Maybe."""
        # TODO: maybe

    def bump_versions(self, save_changes=False, current_versions=None):
        """Bump the versions of all production rules included in a release and optionally save changes."""
        return manage_versions(self.rules, current_versions=current_versions, save_changes=save_changes)

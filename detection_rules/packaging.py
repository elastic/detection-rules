# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Packaging and preparation for releases."""
import base64
import hashlib
import json
import os
import shutil
from collections import OrderedDict

import click

from . import rule_loader
from .misc import JS_LICENSE
from .rule import Rule  # noqa: F401
from .utils import get_path, get_etc_path

RELEASE_DIR = get_path("releases")
PACKAGE_FILE = get_etc_path('packages.yml')
RULE_VERSIONS = get_etc_path('version.lock.json')
NOTICE_FILE = get_path('NOTICE.txt')


def filter_rule(rule, config_filter):  # type: (Rule,dict) -> bool  # rule.contents (not api), filter_dict -> match
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

    return True


def manage_versions(rules, current_versions=None, exclude_version_update=False, add_new=True, save_changes=False,
                    verbose=True):
    # type: (list, dict, bool, bool, bool, bool) -> [list, list]
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

    # update the document with the new rules
    if new_rules or changed_rules:
        if verbose:
            click.echo('Rule hash changes detected!')

        if save_changes:
            current_versions.update(new_rules if add_new else {})
            current_versions = OrderedDict(sorted(current_versions.items(), key=lambda x: x[1]['rule_name']))

            with open(RULE_VERSIONS, 'w') as f:
                json.dump(current_versions, f, indent=2, sort_keys=True)

                if verbose:
                    click.echo('Updated version.lock.json file with:')
        else:
            if verbose:
                click.echo('run `build-release --update-version-lock` to update the version.lock.json file')

        if verbose:
            if changed_rules:
                click.echo(' - {} changed rule version(s)'.format(len(changed_rules)))
            if new_rules:
                click.echo(' - {} new rule version addition(s)'.format(len(new_rules)))

    return changed_rules, new_rules.keys()


class Package(object):
    """Packaging object for siem rules and releases."""

    def __init__(self, rules, name, release=False, current_versions=None, min_version=None, max_version=None,
                 update_version_lock=False):
        """Initialize a package."""
        self.rules = [r.copy() for r in rules]  # type: list[Rule]
        self.name = name
        self.release = release

        self.changed_rules, self.new_rules = self._add_versions(current_versions, update_version_lock)

        if min_version or max_version:
            self.rules = [r for r in self.rules
                          if (min_version or 0) <= r.contents['version'] <= (max_version or r.contents['version'])]

    def _add_versions(self, current_versions, update_versions_lock=False):
        """Add versions to rules at load time."""
        return manage_versions(self.rules, current_versions=current_versions, save_changes=update_versions_lock)

    @staticmethod
    def _package_notice_file(save_dir):
        """Convert and save notice file with package."""
        with open(NOTICE_FILE, 'rt') as f:
            notice_txt = f.read()

        with open(os.path.join(save_dir, 'notice.ts'), 'wt') as f:
            commented_notice = [' * ' + line for line in notice_txt.splitlines()]
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
            ''
        ]
        rule_imports = [f"import rule{i} from './{os.path.splitext(os.path.basename(r.path))[0] + '.json'}';"
                        for i, r in enumerate(sorted_rules, 1)]
        const_exports = ['export const rawRules = [']
        const_exports.extend(f"  rule{i}," for i, _ in enumerate(sorted_rules, 1))
        const_exports.append("];")
        const_exports.append(" ")

        index_ts = [JS_LICENSE + '\n'] + comments + rule_imports + const_exports
        with open(os.path.join(save_dir, 'index.ts'), 'wt') as f:
            f.write('\n'.join(index_ts))

    def save_release_files(self, directory, changed_rules, new_rules):
        """Release a package."""
        with open(os.path.join(directory, '{}-summary.txt'.format(self.name)), 'w') as f:
            f.write(self.generate_summary(changed_rules, new_rules))
        with open(os.path.join(directory, '{}-consolidated.json'.format(self.name)), 'w') as f:
            json.dump(json.loads(self.get_consolidated()), f, sort_keys=True, indent=2)

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
            self.save_release_files(extras_dir, self.changed_rules, self.new_rules)

            # zip all rules only and place in extras
            shutil.make_archive(os.path.join(extras_dir, self.name), 'zip', root_dir=os.path.dirname(rules_dir),
                                base_dir=os.path.basename(rules_dir))

            # zip everything and place in release root
            shutil.make_archive(os.path.join(save_dir, '{}-all'.format(self.name)), 'zip',
                                root_dir=os.path.dirname(extras_dir), base_dir=os.path.basename(extras_dir))

        if verbose:
            click.echo('Package saved to: {}'.format(save_dir))

    def from_github(self):
        """Retrieve previously released and staged packages."""

    def get_package_hash(self, as_api=True, verbose=True):
        """Get hash of package contents."""
        contents = base64.b64encode(self.get_consolidated(as_api=as_api).encode('utf-8'))
        sha256 = hashlib.sha256(contents).hexdigest()

        if verbose:
            click.echo('- sha256: {}'.format(sha256))

        return sha256

    @classmethod
    def from_config(cls, config=None, update_version_lock=False):  # type: (dict, bool) -> Package
        """Load a rules package given a config."""
        all_rules = rule_loader.load_rules(verbose=False).values()
        config = config or {}
        rule_filter = config.pop('filter', {})
        min_version = config.pop('min_version', None)
        max_version = config.pop('max_version', None)

        rules = filter(lambda rule: filter_rule(rule, rule_filter), all_rules)
        update = config.pop('update', {})
        package = cls(rules, min_version=min_version, max_version=max_version, update_version_lock=update_version_lock,
                      **config)

        # Allow for some fields to be overwritten
        if update.get('data', {}):
            for rule in package.rules:
                for sub_dict, values in update.items():
                    rule.contents[sub_dict].update(values)

        return package

    def generate_summary(self, changed_rules, new_rules):
        """Generate stats on package."""
        ecs_versions = set()
        indices = set()
        changed = []
        new = []

        for rule in self.rules:
            ecs_versions.update(rule.ecs_version)
            indices.update(rule.contents.get('index', ''))

            if rule.id in changed_rules:
                changed.append('{} (v{})'.format(rule.name, rule.contents.get('version')))
            elif rule.id in new_rules:
                new.append('{} (v{})'.format(rule.name, rule.contents.get('version')))

        total = 'Total Rules: {}'.format(len(self.rules))
        sha256 = 'Package Hash: {}'.format(self.get_package_hash(verbose=False))
        ecs_versions = 'ECS Versions: {}'.format(', '.join(ecs_versions))
        indices = 'Included Indexes: {}'.format(', '.join(indices))
        new_rules = 'New Rules: \n{}'.format('\n'.join(' - ' + s for s in sorted(new)) if new else 'N/A')
        modified_rules = 'Modified Rules: \n{}'.format('\n'.join(' - ' + s for s in sorted(changed)) if new else 'N/A')
        return '\n'.join([total, sha256, ecs_versions, indices, new_rules, modified_rules])

    def bump_versions(self, save_changes=False, current_versions=None):
        """Bump the versions of all production rules included in a release and optionally save changes."""
        return manage_versions(self.rules, current_versions=current_versions, save_changes=save_changes)

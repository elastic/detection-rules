# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.
"""Helper utilities to manage the version lock."""
from copy import deepcopy
from typing import List, Optional

import click

from .rule_loader import RuleCollection
from .semver import Version
from .utils import dict_hash, load_etc_dump, save_etc_dump, cached

ETC_VERSION_LOCK_FILE = "version.lock.json"
ETC_DEPRECATED_RULES_FILE = "deprecated_rules.json"
MIN_LOCK_VERSION_DEFAULT = Version("7.13.0")


def _convert_lock_version(stack_version: Optional[str]) -> Version:
    """Convert an optional stack version to the minimum for the lock."""
    if stack_version is None:
        return MIN_LOCK_VERSION_DEFAULT
    return max(Version(stack_version), MIN_LOCK_VERSION_DEFAULT)


@cached
def load_versions():
    """Load the versions file."""
    return load_etc_dump(ETC_VERSION_LOCK_FILE)


class VersionLock:
    """Version handling for rule files and collections."""

    def __init__(self, version_lock_file: Optional[str] = None, deprecated_lock_file: Optional[str] = None,
                 version_lock: Optional[dict] = None, deprecated_lock: Optional[dict] = None,
                 name: Optional[str] = None):
        assert (version_lock_file or version_lock), 'Must provide version lock file or contents'
        assert (deprecated_lock_file or deprecated_lock), 'Must provide deprecated lock file or contents'

        self.name = name
        self.version_lock_file = version_lock_file
        self.deprecated_lock_file = deprecated_lock_file

        self.version_lock = load_etc_dump(self.version_lock_file) if version_lock_file else version_lock
        self.deprecated_lock = load_etc_dump(self.deprecated_lock_file) if deprecated_lock_file else deprecated_lock

    def save_versions(self, current_versions: dict):
        save_etc_dump(current_versions, self.version_lock_file)
        print('Updated version.lock.json file')

    def get_locked_version(self, rule_id: str, min_stack_version: Optional[str] = None) -> Optional[int]:
        if rule_id in self.version_lock:
            latest_version_info = self.version_lock[rule_id]
            stack_version_info = latest_version_info.get("previous", {}).get(min_stack_version, latest_version_info)
            return stack_version_info['version']

    def get_locked_hash(self, rule_id: str, min_stack_version: Optional[str] = None) -> Optional[str]:
        """Get the version info matching the min_stack_version if present."""
        if rule_id in self.version_lock:
            latest_version_info = self.version_lock[rule_id]
            stack_version_info = latest_version_info.get("previous", {}).get(min_stack_version, latest_version_info)
            existing_sha256: str = stack_version_info['sha256']
            return existing_sha256

    def manage_versions(self, rules: RuleCollection,
                        exclude_version_update=False, save_changes=False,
                        verbose=True) -> (List[str], List[str], List[str]):
        """Update the contents of the version.lock file and optionally save changes."""
        from .packaging import current_stack_version

        lock_file_contents = deepcopy(self.version_lock)
        version_lock_hash = dict_hash(lock_file_contents)
        current_deprecated_lock = deepcopy(self.deprecated_lock)

        verbose_echo = click.echo if verbose else (lambda x: None)

        already_deprecated = set(current_deprecated_lock)
        deprecated_rules = set(rules.deprecated.id_map)
        new_rules = set(rule.id for rule in rules if rule.contents.latest_version is None) - deprecated_rules
        changed_rules = set(rule.id for rule in rules if rule.contents.is_dirty) - deprecated_rules

        # manage deprecated rules
        newly_deprecated = deprecated_rules - already_deprecated

        if not (new_rules or changed_rules or newly_deprecated):
            return list(changed_rules), list(new_rules), list(newly_deprecated)

        verbose_echo('Rule changes detected!')

        route = None
        existing_rule_lock = {}
        original_hash = None
        changes = []

        def add_changes(r, *msg):
            if not original_hash or original_hash != current_rule_lock['sha256']:
                new = [f'  {route}: {r.id}, new version: {existing_rule_lock["version"]}']
                new.extend([f'    - {m}' for m in msg if m])
                changes.extend(new)

        for rule in rules:
            if rule.contents.metadata.maturity == "production" or rule.id in newly_deprecated:
                # assume that older stacks are always locked first
                min_stack = _convert_lock_version(rule.contents.metadata.min_stack_version)

                current_rule_lock = rule.contents.lock_info(bump=not exclude_version_update)
                existing_rule_lock: dict = lock_file_contents.setdefault(rule.id, {})
                original_hash = existing_rule_lock.get('sha256')

                # prevent rule type changes for already locked and released rules (#1854)
                if existing_rule_lock:
                    name = current_rule_lock['rule_name']
                    existing_type = existing_rule_lock['type']
                    current_type = current_rule_lock['type']
                    if existing_type != current_type:
                        err_msg = f'cannot change "type" in locked rule: {name} from {existing_type} to {current_type}'
                        raise ValueError(err_msg)

                # scenarios to handle, assuming older stacks are always locked first:
                # 1) no breaking changes ever made or the first time a rule is created
                # 2) on the latest, after a breaking change has been locked
                # 3) on the latest stack, locking in a breaking change
                # 4) on an old stack, after a breaking change has been made
                latest_locked_stack_version = _convert_lock_version(existing_rule_lock.get("min_stack_version"))

                if not existing_rule_lock or min_stack == latest_locked_stack_version:
                    route = 'A'
                    # 1) no breaking changes ever made or the first time a rule is created
                    # 2) on the latest, after a breaking change has been locked
                    existing_rule_lock.update(current_rule_lock)

                    # add the min_stack_version to the lock if it's explicitly set
                    log_msg = None
                    if rule.contents.metadata.min_stack_version is not None:
                        existing_rule_lock["min_stack_version"] = str(min_stack)
                        log_msg = f'min_stack_version added: {min_stack}'

                    add_changes(rule, log_msg)

                elif min_stack > latest_locked_stack_version:
                    route = 'B'
                    # 3) on the latest stack, locking in a breaking change
                    previous_lock_info = {
                        "rule_name": existing_rule_lock["rule_name"],
                        "sha256": existing_rule_lock["sha256"],
                        "version": existing_rule_lock["version"],
                    }
                    existing_rule_lock.setdefault("previous", {})

                    # move the current locked info into the previous section
                    existing_rule_lock["previous"][str(latest_locked_stack_version)] = previous_lock_info

                    # overwrite the "latest" part of the lock at the top level
                    # TODO: would need to preserve space here as well if supporting forked version spacing
                    existing_rule_lock.update(current_rule_lock, min_stack_version=str(min_stack))
                    add_changes(
                        rule,
                        f'previous {latest_locked_stack_version} saved as version: {previous_lock_info["version"]}',
                        f'current min_stack updated to {min_stack}'
                    )

                elif min_stack < latest_locked_stack_version:
                    route = 'C'
                    # 4) on an old stack, after a breaking change has been made (updated fork)
                    assert str(min_stack) in existing_rule_lock.get("previous", {}), \
                        f"Expected {rule.id} @ v{min_stack} in the rule lock"

                    # TODO: Figure out whether we support locking old versions and if we want to
                    #       "leave room" by skipping versions when breaking changes are made.
                    #       We can still inspect the version lock manually after locks are made,
                    #       since it's a good summary of everything that happens
                    existing_rule_lock["previous"][str(min_stack)] = current_rule_lock
                    existing_rule_lock.update(current_rule_lock)
                    add_changes(rule, f'previous version {min_stack} updated version to {current_rule_lock["version"]}')
                    continue
                else:
                    raise RuntimeError("Unreachable code")

                if 'previous' in existing_rule_lock:
                    current_rule_version = rule.contents.lock_info()['version']
                    for min_stack_version, versioned_lock in existing_rule_lock['previous'].items():
                        existing_lock_version = versioned_lock['version']
                        if current_rule_version < existing_lock_version:
                            raise ValueError(f'{rule.id} - previous {min_stack_version=} {existing_lock_version=} '
                                             f'has a higher version than {current_rule_version=}')

        for rule in rules.deprecated:
            if rule.id in newly_deprecated:
                current_deprecated_lock[rule.id] = {
                    "rule_name": rule.name,
                    "stack_version": current_stack_version(),
                    "deprecation_date": rule.contents.metadata['deprecation_date']
                }

        if save_changes or verbose:
            click.echo(f' - {len(changed_rules)} changed rules')
            click.echo(f' - {len(new_rules)} new rules')
            click.echo(f' - {len(newly_deprecated)} newly deprecated rules')

        if save_changes:
            click.echo('Detailed changes: \n' + '\n'.join(changes))

        if not save_changes:
            verbose_echo(
                'run `build-release --update-version-lock` to update version.lock.json and deprecated_rules.json')
            return list(changed_rules), list(new_rules), list(newly_deprecated)

        new_hash = dict_hash(lock_file_contents)

        if version_lock_hash != new_hash:
            save_etc_dump(lock_file_contents, ETC_VERSION_LOCK_FILE)
            click.echo('Updated version.lock.json file')

            # reset local version lock
            self.version_lock = lock_file_contents

        if newly_deprecated:
            save_etc_dump(current_deprecated_lock, ETC_DEPRECATED_RULES_FILE)
            click.echo('Updated deprecated_rules.json file')

            # reset local version lock
            self.deprecated_lock = current_deprecated_lock

        return changed_rules, list(new_rules), newly_deprecated


default_version_lock = VersionLock(ETC_VERSION_LOCK_FILE, ETC_DEPRECATED_RULES_FILE, name='default')

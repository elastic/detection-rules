# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.
"""Helper utilities to manage the version lock."""
from typing import List, Optional

import click

from .rule import TOMLRule
from .utils import dict_hash, load_etc_dump, save_etc_dump, cached
from .semver import Version


ETC_VERSION_LOCK_FILE = "version.lock.json"
ETC_DEPRECATED_RULES_FILE = "deprecated_rules.json"
MIN_LOCK_VERSION_DEFAULT = Version("7.13.0")


def _convert_lock_version(stack_version: Optional[str]) -> Version:
    """Convert an optional stack version to the minimum for the lock."""
    if stack_version is None:
        return MIN_LOCK_VERSION_DEFAULT
    return max(Version(stack_version), MIN_LOCK_VERSION_DEFAULT)

@cached
def get_locked_hash(rule_id: str, min_stack_version: Optional[str] = None) -> Optional[str]:
    rules_versions = load_versions()

    # Get the version info matching the min_stack_version if present
    if rule_id in rules_versions:
        rule_lock_info = rules_versions[rule_id]
        version_info = rule_lock_info.get("previous_stacks", {}).get(min_stack_version, rule_lock_info)
        existing_sha256: str = version_info['sha256']
        return existing_sha256


def manage_versions(rules: List[TOMLRule],
                    exclude_version_update=False, save_changes=False,
                    verbose=True) -> (List[str], List[str], List[str]):
    """Update the contents of the version.lock file and optionally save changes."""
    from .packaging import current_stack_version

    current_versions = load_versions()
    versions_hash = dict_hash(current_versions)
    rule_deprecations = load_etc_dump(ETC_DEPRECATED_RULES_FILE)

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

    for rule in rules:
        if rule.contents.metadata.maturity == "production" or rule.id in newly_deprecated:
            # assume that older stacks are always locked first
            min_stack = _convert_lock_version(rule.contents.metadata.min_stack_version)

            lock_info = rule.contents.lock_info(bump=not exclude_version_update)
            current_rule_lock: dict = current_versions.get(rule.id, {})

            # scenarios to handle, assuming older stacks are always locked first:
            # 1) no breaking changes ever made or the first time a rule is created
            # 2) on an old stack, before a breaking change
            # 3) on a new stack, locking in a breaking change
            # 4) on a new stack, after a breaking change has been locked
            latest_locked_stack_version = _convert_lock_version(current_rule_lock.get("min_stack_version"))

            if min_stack == latest_locked_stack_version:
                # at the latest, just create/update the lock entry
                current_versions.setdefault(rule.id, {}).update(lock_info)

                # add the min_stack_version to the lock if it's explicitly set
                if rule.contents.metadata.min_stack_version is not None:
                    current_versions[rule.id]["min_stack_version"] = str(min_stack)

            elif min_stack < latest_locked_stack_version:
                # current stack is later that the most recently locked version
                assert str(min_stack) in current_rule_lock.get("previous", {}), \
                    f"Expected a lock for {rule.id} @ v{min_stack}"

                current_rule_lock["previous"][str(min_stack)] = lock_info
                continue

            elif min_stack > latest_locked_stack_version:
                # detected a breaking change. push the latest locked changes into .previous
                previous_lock_info = {
                    "rule_name":  current_rule_lock["rule_name"],
                    "sha256":  current_rule_lock["sha256"],
                    "version":  current_rule_lock["version"],
                }
                current_rule_lock.setdefault("previous", {})[str(latest_locked_stack_version)] = previous_lock_info
                current_rule_lock.update(lock_info, min_stack_version=str(latest_locked_stack_version))

            else:
                raise RuntimeError("Unreachable code")

    for rule in rules:
        if rule.id in newly_deprecated:
            rule_deprecations[rule.id] = {
                "rule_name": rule.name,
                "stack_version": current_stack_version,
                "deprecation_date": rule.contents.metadata.deprecation_date
            }

    if not save_changes:
        echo('run `build-release --update-version-lock` to update version.lock.json and deprecated_rules.json')
        return list(changed_rules), list(new_rules), list(newly_deprecated)

    new_hash = dict_hash(current_versions)

    if versions_hash != new_hash:
        save_etc_dump(current_versions, ETC_VERSION_LOCK_FILE)
        echo('Updated version.lock.json file')

    if newly_deprecated:
        save_etc_dump(rule_deprecations, ETC_DEPRECATED_RULES_FILE)
        echo('Updated deprecated_rules.json file')

    echo(f' - {len(changed_rules)} changed rules')
    echo(f' - {len(new_rules)} new rules')
    echo(f' - {len(newly_deprecated)} newly deprecated rules')

    return changed_rules, list(new_rules), newly_deprecated


@cached
def load_versions():
    """Load the versions file."""
    return load_etc_dump(ETC_VERSION_LOCK_FILE)


def save_versions(current_versions: dict):
    save_etc_dump(current_versions, ETC_VERSION_LOCK_FILE)
    print('Updated version.lock.json file')

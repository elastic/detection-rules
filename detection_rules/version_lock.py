from typing import List

import click

from .rule import TOMLRule
from .utils import dict_hash, load_etc_dump, save_etc_dump, cached


def manage_versions(rules: List[TOMLRule], current_versions: dict = None,
                    exclude_version_update=False, save_changes=False,
                    verbose=True) -> (List[str], List[str], List[str]):
    """Update the contents of the version.lock file and optionally save changes."""
    from .packaging import current_stack_version

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


@cached
def load_versions():
    """Load the versions file."""
    return load_etc_dump('version.lock.json')


def save_versions(current_versions: dict):
    save_etc_dump(current_versions, 'version.lock.json')
    print('Updated version.lock.json file')

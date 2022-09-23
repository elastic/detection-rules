# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.
"""Helper utilities to manage the version lock."""
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Dict, List, Optional, Union

import click

from .mixins import LockDataclassMixin, MarshmallowDataclassMixin
from .rule_loader import RuleCollection
from .schemas import definitions
from .semver import Version
from .utils import cached, get_etc_path

ETC_VERSION_LOCK_FILE = "version.lock.json"
ETC_VERSION_LOCK_PATH = Path(get_etc_path()) / ETC_VERSION_LOCK_FILE
ETC_DEPRECATED_RULES_FILE = "deprecated_rules.json"
ETC_DEPRECATED_RULES_PATH = Path(get_etc_path()) / ETC_DEPRECATED_RULES_FILE

# This was the original version the lock was created under. This constant has been replaced by
# schemas.get_min_supported_stack_version to dynamically determine the minimum
# MIN_LOCK_VERSION_DEFAULT = Version("7.13.0")


@dataclass(frozen=True)
class BaseEntry:
    rule_name: definitions.RuleName
    sha256: definitions.Sha256
    type: definitions.RuleType
    version: definitions.PositiveInteger


@dataclass(frozen=True)
class PreviousEntry(BaseEntry):

    # this is Optional for resiliency in already tagged branches missing this field. This means we should strictly
    # validate elsewhere
    max_allowable_version: Optional[int]


@dataclass(frozen=True)
class VersionLockFileEntry(MarshmallowDataclassMixin, BaseEntry):
    """Schema for a rule entry in the version lock."""
    min_stack_version: Optional[definitions.SemVerMinorOnly]
    previous: Optional[Dict[definitions.SemVerMinorOnly, PreviousEntry]]


@dataclass(frozen=True)
class VersionLockFile(LockDataclassMixin):
    """Schema for the full version lock file."""
    data: Dict[Union[definitions.UUIDString, definitions.KNOWN_BAD_RULE_IDS], VersionLockFileEntry]
    file_path: ClassVar[Path] = ETC_VERSION_LOCK_PATH

    def __contains__(self, rule_id: str):
        """Check if a rule is in the map by comparing IDs."""
        return rule_id in self.data

    def __getitem__(self, item) -> VersionLockFileEntry:
        """Return entries by rule id."""
        if item not in self.data:
            raise KeyError(item)
        return self.data[item]


@dataclass(frozen=True)
class DeprecatedRulesEntry(MarshmallowDataclassMixin):
    """Schema for rule entry in the deprecated rules file."""
    deprecation_date: Union[definitions.Date, definitions.KNOWN_BAD_DEPRECATED_DATES]
    rule_name: definitions.RuleName
    stack_version: definitions.SemVer


@dataclass(frozen=True)
class DeprecatedRulesFile(LockDataclassMixin):
    """Schema for the full deprecated rules file."""
    data: Dict[Union[definitions.UUIDString, definitions.KNOWN_BAD_RULE_IDS], DeprecatedRulesEntry]
    file_path: ClassVar[Path] = ETC_DEPRECATED_RULES_PATH

    def __contains__(self, rule_id: str):
        """Check if a rule is in the map by comparing IDs."""
        return rule_id in self.data

    def __getitem__(self, item) -> DeprecatedRulesEntry:
        """Return entries by rule id."""
        if item not in self.data:
            raise KeyError(item)
        return self.data[item]


@cached
def load_versions() -> dict:
    """Load and validate the default version.lock file."""
    version_lock_file = VersionLockFile.load_from_file()
    return version_lock_file.to_dict()


# for tagged branches which existed before the types were added and validation enforced, we will need to manually add
# them to allow them to pass validation. These will only ever currently be loaded via the RuleCollection.load_git_tag
# method, which is primarily for generating diffs across releases, so there is no risk to versioning
def add_rule_types_to_lock(lock_contents: dict, rule_map: Dict[str, dict]):
    """Add the rule type to entries in the lock file,if missing."""
    for rule_id, lock in lock_contents.items():
        rule = rule_map.get(rule_id, {})

        # this defaults to query if the rule is not found - it is just for validation so should not impact
        rule_type = rule.get('rule', {}).get('type', 'query')

        # the type is a bit less important than the structure to pass validation
        lock['type'] = rule_type

        if 'previous' in lock:
            for _, prev_lock in lock['previous'].items():
                prev_lock['type'] = rule_type

    return lock_contents


class VersionLock:
    """Version handling for rule files and collections."""

    def __init__(self, version_lock_file: Optional[Path] = None, deprecated_lock_file: Optional[Path] = None,
                 version_lock: Optional[dict] = None, deprecated_lock: Optional[dict] = None,
                 name: Optional[str] = None):
        assert (version_lock_file or version_lock), 'Must provide version lock file or contents'
        assert (deprecated_lock_file or deprecated_lock), 'Must provide deprecated lock file or contents'

        self.name = name
        self.version_lock_file = version_lock_file
        self.deprecated_lock_file = deprecated_lock_file

        if version_lock_file:
            self.version_lock = VersionLockFile.load_from_file(version_lock_file)
        else:
            self.version_lock = VersionLockFile.from_dict(dict(data=version_lock))

        if deprecated_lock_file:
            self.deprecated_lock = DeprecatedRulesFile.load_from_file(deprecated_lock_file)
        else:
            self.deprecated_lock = DeprecatedRulesFile.from_dict(dict(data=deprecated_lock))

    @staticmethod
    def save_file(path: Path, lock_file: Union[VersionLockFile, DeprecatedRulesFile]):
        assert path, f'{path} not set'
        lock_file.save_to_file(path)
        print(f'Updated {path} file')

    def get_locked_version(self, rule_id: str, min_stack_version: Optional[str] = None) -> Optional[int]:
        if rule_id in self.version_lock:
            latest_version_info = self.version_lock[rule_id]
            if latest_version_info.previous and latest_version_info.previous.get(min_stack_version):
                stack_version_info = latest_version_info.previous.get(min_stack_version)
            else:
                stack_version_info = latest_version_info
            return stack_version_info.version

    def get_locked_hash(self, rule_id: str, min_stack_version: Optional[str] = None) -> Optional[str]:
        """Get the version info matching the min_stack_version if present."""
        if rule_id in self.version_lock:
            latest_version_info = self.version_lock[rule_id]
            if latest_version_info.previous and latest_version_info.previous.get(min_stack_version):
                stack_version_info = latest_version_info.previous.get(min_stack_version)
            else:
                stack_version_info = latest_version_info
            existing_sha256: str = stack_version_info.sha256
            return existing_sha256

    def manage_versions(self, rules: RuleCollection,
                        exclude_version_update=False, save_changes=False,
                        verbose=True) -> (List[str], List[str], List[str]):
        """Update the contents of the version.lock file and optionally save changes."""
        from .packaging import current_stack_version

        version_lock_hash = self.version_lock.sha256()
        lock_file_contents = deepcopy(self.version_lock.to_dict())
        current_deprecated_lock = deepcopy(self.deprecated_lock.to_dict())

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
        changes = []

        def log_changes(r, route_taken, new_rule_version, *msg):
            new = [f'  {route_taken}: {r.id}, new version: {new_rule_version}']
            new.extend([f'    - {m}' for m in msg if m])
            changes.extend(new)

        for rule in rules:
            if rule.contents.metadata.maturity == "production" or rule.id in newly_deprecated:
                # assume that older stacks are always locked first
                min_stack = Version(rule.contents.get_supported_version())

                lock_from_rule = rule.contents.lock_info(bump=not exclude_version_update)
                lock_from_file: dict = lock_file_contents.setdefault(rule.id, {})

                # prevent rule type changes for already locked and released rules (#1854)
                if lock_from_file:
                    name = lock_from_rule['rule_name']
                    existing_type = lock_from_file['type']
                    current_type = lock_from_rule['type']
                    if existing_type != current_type:
                        err_msg = f'cannot change "type" in locked rule: {name} from {existing_type} to {current_type}'
                        raise ValueError(err_msg)

                # scenarios to handle, assuming older stacks are always locked first:
                # 1) no breaking changes ever made or the first time a rule is created
                # 2) on the latest, after a breaking change has been locked
                # 3) on the latest stack, locking in a breaking change
                # 4) on an old stack, after a breaking change has been made
                latest_locked_stack_version = rule.contents.convert_supported_version(
                    lock_from_file.get("min_stack_version"))

                if not lock_from_file or min_stack == latest_locked_stack_version:
                    route = 'A'
                    # 1) no breaking changes ever made or the first time a rule is created
                    # 2) on the latest, after a breaking change has been locked
                    lock_from_file.update(lock_from_rule)
                    new_version = lock_from_rule['version']

                    # add the min_stack_version to the lock if it's explicitly set
                    if rule.contents.metadata.min_stack_version is not None:
                        lock_from_file["min_stack_version"] = str(min_stack)
                        log_msg = f'min_stack_version added: {min_stack}'
                        log_changes(rule, route, new_version, log_msg)

                elif min_stack > latest_locked_stack_version:
                    route = 'B'
                    # 3) on the latest stack, locking in a breaking change
                    previous_lock_info = {
                        "max_allowable_version": lock_from_rule['version'] - 1,
                        "rule_name": lock_from_file["rule_name"],
                        "sha256": lock_from_file["sha256"],
                        "version": lock_from_file["version"],
                        "type": lock_from_file["type"]
                    }
                    lock_from_file.setdefault("previous", {})

                    # move the current locked info into the previous section
                    lock_from_file["previous"][str(latest_locked_stack_version)] = previous_lock_info

                    # overwrite the "latest" part of the lock at the top level
                    # TODO: would need to preserve space here as well if supporting forked version spacing
                    lock_from_file.update(lock_from_rule, min_stack_version=str(min_stack))
                    new_version = lock_from_rule['version']
                    log_changes(
                        rule, route, new_version,
                        f'previous {latest_locked_stack_version} saved as version: {previous_lock_info["version"]}',
                        f'current min_stack updated to {min_stack}'
                    )

                elif min_stack < latest_locked_stack_version:
                    route = 'C'
                    # 4) on an old stack, after a breaking change has been made (updated fork)
                    assert str(min_stack) in lock_from_file.get("previous", {}), \
                        f"Expected {rule.id} @ v{min_stack} in the rule lock"

                    # TODO: Figure out whether we support locking old versions and if we want to
                    #       "leave room" by skipping versions when breaking changes are made.
                    #       We can still inspect the version lock manually after locks are made,
                    #       since it's a good summary of everything that happens

                    previous_entry = lock_from_file["previous"][str(min_stack)]
                    max_allowable_version = previous_entry['max_allowable_version']

                    # if version bump collides with future bump: fail
                    # if space: change and log
                    info_from_rule = (lock_from_rule['sha256'], lock_from_rule['version'])
                    info_from_file = (previous_entry['sha256'], previous_entry['version'])

                    if lock_from_rule['version'] > max_allowable_version:
                        raise ValueError(f'Forked rule: {rule.id} - {rule.name} has changes that will force it to '
                                         f'exceed the max allowable version of {max_allowable_version}')

                    if info_from_rule != info_from_file:
                        lock_from_file["previous"][str(min_stack)].update(lock_from_rule)
                        new_version = lock_from_rule["version"]
                        log_changes(rule, route, 'unchanged',
                                    f'previous version {min_stack} updated version to {new_version}')
                    continue
                else:
                    raise RuntimeError("Unreachable code")

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

        if not save_changes:
            verbose_echo(
                'run `build-release --update-version-lock` to update version.lock.json and deprecated_rules.json')
            return list(changed_rules), list(new_rules), list(newly_deprecated)

        click.echo('Detailed changes: \n' + '\n'.join(changes))

        # reset local version lock
        self.version_lock = VersionLockFile.from_dict(dict(data=lock_file_contents))
        self.deprecated_lock = DeprecatedRulesFile.from_dict(dict(data=current_deprecated_lock))

        new_hash = self.version_lock.sha256()

        if version_lock_hash != new_hash:
            self.save_file(self.version_lock_file, self.version_lock)

        if newly_deprecated:
            self.save_file(self.deprecated_lock_file, self.deprecated_lock)

        return changed_rules, list(new_rules), newly_deprecated


default_version_lock = VersionLock(ETC_VERSION_LOCK_PATH, ETC_DEPRECATED_RULES_PATH, name='default')

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Load rule metadata transform between rule and api formats."""
import io
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Iterable, Callable, Optional, Union

import click
import pytoml
from marshmallow.exceptions import ValidationError

from . import utils
from .mappings import RtaMappings
from .rule import DeprecatedRule, DeprecatedRuleContents, TOMLRule, TOMLRuleContents
from .schemas import definitions
from .utils import get_path, cached

DEFAULT_RULES_DIR = Path(get_path("rules"))
DEFAULT_DEPRECATED_DIR = DEFAULT_RULES_DIR / '_deprecated'
RTA_DIR = get_path("rta")
FILE_PATTERN = r'^([a-z0-9_])+\.(json|toml)$'


def path_getter(value: str) -> Callable[[dict], bool]:
    """Get the path from a Python object."""
    path = value.replace("__", ".").split(".")

    def callback(obj: dict):
        for p in path:
            if isinstance(obj, dict) and p in path:
                obj = obj[p]
            else:
                return None

        return obj

    return callback


def dict_filter(_obj: Optional[dict] = None, **critieria) -> Callable[[dict], bool]:
    """Get a callable that will return true if a dictionary matches a set of criteria.

    * each key is a dotted (or __ delimited) path into a dictionary to check
    * each value is a value or list of values to match
    """
    critieria.update(_obj or {})
    checkers = [(path_getter(k), set(v) if isinstance(v, (list, set, tuple)) else {v}) for k, v in critieria.items()]

    def callback(obj: dict) -> bool:
        for getter, expected in checkers:
            target_values = getter(obj)
            target_values = set(target_values) if isinstance(target_values, (list, set, tuple)) else {target_values}

            return bool(expected.intersection(target_values))

        return False

    return callback


def metadata_filter(**metadata) -> Callable[[TOMLRule], bool]:
    """Get a filter callback based off rule metadata"""
    flt = dict_filter(metadata)

    def callback(rule: TOMLRule) -> bool:
        target_dict = rule.contents.metadata.to_dict()
        return flt(target_dict)

    return callback


production_filter = metadata_filter(maturity="production")


def load_locks_from_tag(remote: str, tag: str) -> (str, dict, dict):
    """Loads version and deprecated lock files from git tag."""
    import json
    git = utils.make_git()

    exists_args = ['ls-remote']
    if remote:
        exists_args.append(remote)
    exists_args.append(f'refs/tags/{tag}')

    assert git(*exists_args), f'tag: {tag} does not exist in {remote or "local"}'

    fetch_tags = ['fetch']
    if remote:
        fetch_tags += [remote, '--tags', '-f', tag]
    else:
        fetch_tags += ['--tags', '-f', tag]

    git(*fetch_tags)

    commit_hash = git('rev-list', '-1', tag)
    version = json.loads(git('show', f'{tag}:etc/version.lock.json'))
    deprecated = json.loads(git('show', f'{tag}:etc/deprecated_rules.json'))
    return commit_hash, version, deprecated


@dataclass
class BaseCollection:
    """Base class for collections."""

    rules: list

    def __len__(self):
        """Get the total amount of rules in the collection."""
        return len(self.rules)

    def __iter__(self):
        """Iterate over all rules in the collection."""
        return iter(self.rules)


@dataclass
class DeprecatedCollection(BaseCollection):
    """Collection of loaded deprecated rule dicts."""

    id_map: Dict[str, DeprecatedRule] = field(default_factory=dict)
    file_map: Dict[Path, DeprecatedRule] = field(default_factory=dict)
    rules: List[DeprecatedRule] = field(default_factory=list)

    def __contains__(self, rule: DeprecatedRule):
        """Check if a rule is in the map by comparing IDs."""
        return rule.id in self.id_map

    def filter(self, cb: Callable[[DeprecatedRule], bool]) -> 'RuleCollection':
        """Retrieve a filtered collection of rules."""
        filtered_collection = RuleCollection()

        for rule in filter(cb, self.rules):
            filtered_collection.add_deprecated_rule(rule)

        return filtered_collection


class RuleCollection(BaseCollection):
    """Collection of rule objects."""

    __default = None

    def __init__(self, rules: Optional[List[TOMLRule]] = None):
        from .version_lock import VersionLock

        self.id_map: Dict[definitions.UUIDString, TOMLRule] = {}
        self.file_map: Dict[Path, TOMLRule] = {}
        self.rules: List[TOMLRule] = []
        self.deprecated: DeprecatedCollection = DeprecatedCollection()
        self.errors: Dict[Path, Exception] = {}
        self.frozen = False

        self._toml_load_cache: Dict[Path, dict] = {}
        self._version_lock: Optional[VersionLock] = None

        for rule in (rules or []):
            self.add_rule(rule)

    def __contains__(self, rule: TOMLRule):
        """Check if a rule is in the map by comparing IDs."""
        return rule.id in self.id_map

    def filter(self, cb: Callable[[TOMLRule], bool]) -> 'RuleCollection':
        """Retrieve a filtered collection of rules."""
        filtered_collection = RuleCollection()

        for rule in filter(cb, self.rules):
            filtered_collection.add_rule(rule)

        return filtered_collection

    @staticmethod
    def deserialize_toml_string(contents: Union[bytes, str]) -> dict:
        return pytoml.loads(contents)

    def _load_toml_file(self, path: Path) -> dict:
        if path in self._toml_load_cache:
            return self._toml_load_cache[path]

        # use pytoml instead of toml because of annoying bugs
        # https://github.com/uiri/toml/issues/152
        # might also be worth looking at https://github.com/sdispater/tomlkit
        with io.open(path, "r", encoding="utf-8") as f:
            toml_dict = self.deserialize_toml_string(f.read())
            self._toml_load_cache[path] = toml_dict
            return toml_dict

    def _get_paths(self, directory: Path, recursive=True) -> List[Path]:
        return sorted(directory.rglob('*.toml') if recursive else directory.glob('*.toml'))

    def _assert_new(self, rule: Union[TOMLRule, DeprecatedRule], is_deprecated=False):
        if is_deprecated:
            id_map = self.deprecated.id_map
            file_map = self.deprecated.file_map
        else:
            id_map = self.id_map
            file_map = self.file_map

        assert not self.frozen, f"Unable to add rule {rule.name} {rule.id} to a frozen collection"
        assert rule.id not in id_map, \
            f"Rule ID {rule.id} for {rule.name} collides with rule {id_map.get(rule.id).get('name')}"

        if rule.path is not None:
            rule_path = rule.path.resolve()
            assert rule_path not in file_map, f"Rule file {rule_path} already loaded"
            file_map[rule_path] = rule

    def add_rule(self, rule: TOMLRule):
        self._assert_new(rule)
        self.id_map[rule.id] = rule
        self.rules.append(rule)

    def add_deprecated_rule(self, rule: DeprecatedRule):
        self._assert_new(rule, is_deprecated=True)
        self.deprecated.id_map[rule.id] = rule
        self.deprecated.rules.append(rule)

    def load_dict(self, obj: dict, path: Optional[Path] = None) -> Union[TOMLRule, DeprecatedRule]:
        # bypass rule object load (load_dict) and load as a dict only
        if obj.get('metadata', {}).get('maturity', '') == 'deprecated':
            contents = DeprecatedRuleContents.from_dict(obj)
            contents.set_version_lock(self._version_lock)
            deprecated_rule = DeprecatedRule(path, contents)
            self.add_deprecated_rule(deprecated_rule)
            return deprecated_rule
        else:
            contents = TOMLRuleContents.from_dict(obj)
            contents.set_version_lock(self._version_lock)
            rule = TOMLRule(path=path, contents=contents)
            self.add_rule(rule)
            return rule

    def load_file(self, path: Path) -> Union[TOMLRule, DeprecatedRule]:
        try:
            path = path.resolve()

            # use the default rule loader as a cache.
            # if it already loaded the rule, then we can just use it from that
            if self.__default is not None and self is not self.__default:
                if path in self.__default.file_map:
                    rule = self.__default.file_map[path]
                    self.add_rule(rule)
                    return rule
                elif path in self.__default.deprecated.file_map:
                    deprecated_rule = self.__default.deprecated.file_map[path]
                    self.add_deprecated_rule(deprecated_rule)
                    return deprecated_rule

            obj = self._load_toml_file(path)
            return self.load_dict(obj, path=path)
        except Exception:
            print(f"Error loading rule in {path}")
            raise

    def load_git_tag(self, branch: str, remote: Optional[str] = None, skip_query_validation=False):
        """Load rules from a Git branch."""
        from .version_lock import VersionLock

        commit_hash, v_lock, d_lock = load_locks_from_tag(remote, branch)

        v_lock_name_prefix = f'{remote}/' if remote else ''
        v_lock_name = f'{v_lock_name_prefix}{branch}-{commit_hash}'

        version_lock = VersionLock(version_lock=v_lock, deprecated_lock=d_lock, name=v_lock_name)
        self._version_lock = version_lock

        git = utils.make_git()
        rules_dir = DEFAULT_RULES_DIR.relative_to(get_path("."))
        paths = git("ls-tree", "-r", "--name-only", branch, rules_dir).splitlines()

        for path in paths:
            path = Path(path)
            if path.suffix != ".toml":
                continue

            contents = git("show", f"{branch}:{path}")
            toml_dict = self.deserialize_toml_string(contents)

            if skip_query_validation:
                toml_dict['metadata']['query_schema_validation'] = False

            try:
                self.load_dict(toml_dict, path)
            except ValidationError as e:
                self.errors[path] = e
                continue

    def load_files(self, paths: Iterable[Path]):
        """Load multiple files into the collection."""
        for path in paths:
            self.load_file(path)

    def load_directory(self, directory: Path, recursive=True, toml_filter: Optional[Callable[[dict], bool]] = None):
        paths = self._get_paths(directory, recursive=recursive)
        if toml_filter is not None:
            paths = [path for path in paths if toml_filter(self._load_toml_file(path))]

        self.load_files(paths)

    def load_directories(self, directories: Iterable[Path], recursive=True,
                         toml_filter: Optional[Callable[[dict], bool]] = None):
        for path in directories:
            self.load_directory(path, recursive=recursive, toml_filter=toml_filter)

    def freeze(self):
        """Freeze the rule collection and make it immutable going forward."""
        self.frozen = True

    @classmethod
    def default(cls) -> 'RuleCollection':
        """Return the default rule collection, which retrieves from rules/."""
        if cls.__default is None:
            collection = RuleCollection()
            collection.load_directory(DEFAULT_RULES_DIR)
            collection.freeze()
            cls.__default = collection

        return cls.__default

    def compare_collections(self, other: 'RuleCollection'
                            ) -> (Dict[str, TOMLRule], Dict[str, TOMLRule], Dict[str, DeprecatedRule]):
        """Get the changes between two sets of rules."""
        assert self._version_lock, 'RuleCollection._version_lock must be set for self'
        assert other._version_lock, 'RuleCollection._version_lock must be set for other'

        # we cannot trust the assumption that either of the versions or deprecated files were pre-locked, which means we
        # have to perform additional checks beyond what is done in manage_versions
        changed_rules = {}
        new_rules = {}
        newly_deprecated = {}

        pre_versions_hash = utils.dict_hash(self._version_lock.version_lock)
        post_versions_hash = utils.dict_hash(other._version_lock.version_lock)
        pre_deprecated_hash = utils.dict_hash(self._version_lock.deprecated_lock)
        post_deprecated_hash = utils.dict_hash(other._version_lock.deprecated_lock)

        if pre_versions_hash == post_versions_hash and pre_deprecated_hash == post_deprecated_hash:
            return changed_rules, new_rules, newly_deprecated

        for rule in other:
            if rule.contents.metadata.maturity != 'production':
                continue

            if rule.id not in self.id_map:
                new_rules[rule.id] = rule
            else:
                pre_rule = self.id_map[rule.id]
                if rule.contents.sha256() != pre_rule.contents.sha256():
                    changed_rules[rule.id] = rule

        for rule in other.deprecated:
            if rule.id not in self.deprecated.id_map:
                newly_deprecated[rule.id] = rule

        return changed_rules, new_rules, newly_deprecated


@cached
def load_github_pr_rules(labels: list = None, repo: str = 'elastic/detection-rules', token=None, threads=50,
                         verbose=True) -> (Dict[str, TOMLRule], Dict[str, TOMLRule], Dict[str, list]):
    """Load all rules active as a GitHub PR."""
    import requests
    import pytoml
    from multiprocessing.pool import ThreadPool
    from pathlib import Path
    from .ghwrap import GithubClient

    github = GithubClient(token=token)
    repo = github.client.get_repo(repo)
    labels = set(labels or [])
    open_prs = [r for r in repo.get_pulls() if not labels.difference(set(list(lbl.name for lbl in r.get_labels())))]

    new_rules: List[TOMLRule] = []
    modified_rules: List[TOMLRule] = []
    errors: Dict[str, list] = {}

    existing_rules = RuleCollection.default()
    pr_rules = []

    if verbose:
        click.echo('Downloading rules from GitHub PRs')

    def download_worker(pr_info):
        pull, rule_file = pr_info
        response = requests.get(rule_file.raw_url)
        try:
            raw_rule = pytoml.loads(response.text)
            contents = TOMLRuleContents.from_dict(raw_rule)
            rule = TOMLRule(path=rule_file.filename, contents=contents)
            rule.gh_pr = pull

            if rule in existing_rules:
                modified_rules.append(rule)
            else:
                new_rules.append(rule)

        except Exception as e:
            errors.setdefault(Path(rule_file.filename).name, []).append(str(e))

    for pr in open_prs:
        pr_rules.extend([(pr, f) for f in pr.get_files()
                         if f.filename.startswith('rules/') and f.filename.endswith('.toml')])

    pool = ThreadPool(processes=threads)
    pool.map(download_worker, pr_rules)
    pool.close()
    pool.join()

    new = OrderedDict([(rule.contents.id, rule) for rule in sorted(new_rules, key=lambda r: r.contents.name)])
    modified = OrderedDict()

    for modified_rule in sorted(modified_rules, key=lambda r: r.contents.name):
        modified.setdefault(modified_rule.contents.id, []).append(modified_rule)

    return new, modified, errors


rta_mappings = RtaMappings()

__all__ = (
    "FILE_PATTERN",
    "DEFAULT_RULES_DIR",
    "load_github_pr_rules",
    "DeprecatedCollection",
    "DeprecatedRule",
    "RuleCollection",
    "metadata_filter",
    "production_filter",
    "dict_filter",
    "rta_mappings"
)

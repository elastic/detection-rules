# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Load rule metadata transform between rule and api formats."""
import io
from collections import OrderedDict
from pathlib import Path
from typing import Dict, List, Iterable, Callable, Optional

import click
import pytoml

from .mappings import RtaMappings
from .rule import TOMLRule, TOMLRuleContents
from .schemas import CurrentSchema, definitions
from .utils import get_path, cached

DEFAULT_RULES_DIR = Path(get_path("rules"))
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
deprecate_filter = metadata_filter(maturity="deprecated")


class RuleCollection:
    """Collection of rule objects."""

    __default = None

    def __init__(self, rules: Optional[List[TOMLRule]] = None):
        self.id_map: Dict[definitions.UUIDString, TOMLRule] = {}
        self.file_map: Dict[Path, TOMLRule] = {}
        self.rules: List[TOMLRule] = []
        self.frozen = False

        self._toml_load_cache: Dict[Path, dict] = {}

        for rule in (rules or []):
            self.add_rule(rule)

    def __len__(self):
        """Get the total amount of rules in the collection."""
        return len(self.rules)

    def __iter__(self):
        """Iterate over all rules in the collection."""
        return iter(self.rules)

    def __contains__(self, rule: TOMLRule):
        """Check if a rule is in the map by comparing IDs."""
        return rule.id in self.id_map

    def filter(self, cb: Callable[[TOMLRule], bool]) -> 'RuleCollection':
        """Retrieve a filtered collection of rules."""
        filtered_collection = RuleCollection()

        for rule in filter(cb, self.rules):
            filtered_collection.add_rule(rule)

        return filtered_collection

    def _deserialize_toml(self, path: Path) -> dict:
        if path in self._toml_load_cache:
            return self._toml_load_cache[path]

        # use pytoml instead of toml because of annoying bugs
        # https://github.com/uiri/toml/issues/152
        # might also be worth looking at https://github.com/sdispater/tomlkit
        with io.open(str(path.resolve()), "r", encoding="utf-8") as f:
            toml_dict = pytoml.load(f)
            self._toml_load_cache[path] = toml_dict
            return toml_dict

    def _get_paths(self, directory: Path, recursive=True) -> List[Path]:
        return sorted(directory.rglob('*.toml') if recursive else directory.glob('*.toml'))

    def add_rule(self, rule: TOMLRule):
        assert not self.frozen, f"Unable to add rule {rule.name} {rule.id} to a frozen collection"
        assert rule.id not in self.id_map, \
            f"Rule ID {rule.id} for {rule.name} collides with rule {self.id_map.get(rule.id).name}"

        if rule.path is not None:
            rule.path = rule.path.resolve()
            assert rule.path not in self.file_map, f"Rule file {rule.path} already loaded"
            self.file_map[rule.path] = rule

        self.id_map[rule.id] = rule
        self.rules.append(rule)

    def load_dict(self, obj: dict, path: Optional[Path] = None):
        contents = TOMLRuleContents.from_dict(obj)
        rule = TOMLRule(path=path, contents=contents)
        self.add_rule(rule)

        return rule

    def load_file(self, path: Path) -> TOMLRule:
        try:
            path = path.resolve()

            # use the default rule loader as a cache.
            # if it already loaded the rule, then we can just use it from that
            if self.__default is not None and self is not self.__default and path in self.__default.file_map:
                rule = self.__default.file_map[path]
                self.add_rule(rule)
                return rule

            obj = self._deserialize_toml(path)
            return self.load_dict(obj, path=path)
        except Exception:
            print(f"Error loading rule in {path}")
            raise

    def load_files(self, paths: Iterable[Path]):
        """Load multiple files into the collection."""
        for path in paths:
            self.load_file(path)

    def load_directory(self, directory: Path, recursive=True, toml_filter: Optional[Callable[[dict], bool]] = None):
        paths = self._get_paths(directory, recursive=recursive)
        if toml_filter is not None:
            paths = [path for path in paths if toml_filter(self._deserialize_toml(path))]

        self.load_files(paths)

    def load_directories(self, directories: Iterable[Path], recursive=True,
                         toml_filter: Optional[Callable[[dict], bool]] = None):
        for path in directories:
            self.load_directory(path, recursive=recursive, toml_filter=toml_filter)

    def freeze(self):
        """Freeze the rule collection and make it immutable going forward."""
        self.frozen = True

    @classmethod
    def default(cls):
        """Return the default rule collection, which retrieves from rules/."""
        if cls.__default is None:
            collection = RuleCollection()
            collection.load_directory(DEFAULT_RULES_DIR)
            collection.freeze()
            cls.__default = collection

        return cls.__default


@cached
def load_github_pr_rules(labels: list = None, repo: str = 'elastic/detection-rules', token=None, threads=50,
                         verbose=True):
    """Load all rules active as a GitHub PR."""
    import requests
    import pytoml
    from multiprocessing.pool import ThreadPool
    from pathlib import Path
    from .misc import GithubClient

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
            rule = TOMLRule(rule_file.filename, raw_rule)
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

    new = OrderedDict([(rule.id, rule) for rule in sorted(new_rules, key=lambda r: r.name)])
    modified = OrderedDict()

    for modified_rule in sorted(modified_rules, key=lambda r: r.name):
        modified.setdefault(modified_rule.id, []).append(modified_rule)

    return new, modified, errors


@cached
def get_non_required_defaults_by_type(rule_type: str) -> dict:
    """Get list of fields which are not required for a specified rule type."""
    schema = CurrentSchema.get_schema(rule_type)
    properties = schema['properties']
    non_required_defaults = {prop: properties[prop].get('default') for prop in properties
                             if prop not in schema['required'] and 'default' in properties[prop]}
    return non_required_defaults


def find_unneeded_defaults_from_rule(toml_contents: dict) -> dict:
    """Remove values that are not required in the schema which are set with default values."""
    unrequired_defaults = get_non_required_defaults_by_type(toml_contents['rule']['type'])
    default_matches = {prop: toml_contents["rule"][prop] for prop, val in unrequired_defaults.items()
                       if toml_contents["rule"].get(prop) == val}
    return default_matches


rta_mappings = RtaMappings()


__all__ = (
    "FILE_PATTERN",
    "DEFAULT_RULES_DIR",
    "load_github_pr_rules",
    "get_non_required_defaults_by_type",
    "RuleCollection",
    "metadata_filter",
    "production_filter",
    "dict_filter",
    "find_unneeded_defaults_from_rule",
    "rta_mappings"
)

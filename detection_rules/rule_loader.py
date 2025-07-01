# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Load rule metadata transform between rule and api formats."""

import json
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from multiprocessing.pool import ThreadPool
from pathlib import Path
from subprocess import CalledProcessError
from typing import TYPE_CHECKING, Any

import click
import pytoml  # type: ignore[reportMissingTypeStubs]
import requests
from github.File import File
from github.PullRequest import PullRequest
from marshmallow.exceptions import ValidationError

from . import utils
from .config import parse_rules_config
from .ghwrap import GithubClient
from .rule import DeprecatedRule, DeprecatedRuleContents, DictRule, TOMLRule, TOMLRuleContents
from .utils import cached, get_path

if TYPE_CHECKING:
    from .schemas import definitions
    from .version_lock import VersionLock


RULES_CONFIG = parse_rules_config()
DEFAULT_PREBUILT_RULES_DIRS = RULES_CONFIG.rule_dirs
DEFAULT_PREBUILT_BBR_DIRS = RULES_CONFIG.bbr_rules_dirs
FILE_PATTERN = r"^([a-z0-9_])+\.(json|toml)$"


def path_getter(value: str) -> Callable[[dict[str, Any]], Any]:
    """Get the path from a Python object."""
    path = value.replace("__", ".").split(".")

    def callback(obj: dict[str, Any]) -> Any:
        for p in path:
            if p in path:
                obj = obj[p]
            else:
                return None

        return obj

    return callback


def dict_filter(_obj: dict[str, Any] | None = None, **criteria: Any) -> Callable[[dict[str, Any]], bool]:
    """Get a callable that will return true if a dictionary matches a set of criteria.

    * each key is a dotted (or __ delimited) path into a dictionary to check
    * each value is a value or list of values to match
    """
    criteria.update(_obj or {})
    checkers = [
        # What if v is not be hashable?
        (path_getter(k), set(v if isinstance(v, (list | set | tuple)) else (v,)))  # type: ignore[reportUnknownArgumentType]
        for k, v in criteria.items()
    ]

    def callback(obj: dict[str, Any]) -> bool:
        for getter, expected in checkers:
            target_values = getter(obj)
            target_values = (  # type: ignore[reportUnknownVariableType]
                set(target_values)  # type: ignore[reportUnknownVariableType]
                if isinstance(target_values, (list | set | tuple))
                else {target_values}
            )

            return bool(expected.intersection(target_values))  # type: ignore[reportUnknownArgumentType]

        return False

    return callback


def metadata_filter(**metadata: Any) -> Callable[[TOMLRule], bool]:
    """Get a filter callback based off rule metadata"""
    flt = dict_filter(metadata)

    def callback(rule: TOMLRule) -> bool:
        target_dict = rule.contents.metadata.to_dict()
        return flt(target_dict)

    return callback


production_filter = metadata_filter(maturity="production")


def load_locks_from_tag(
    remote: str,
    tag: str,
    version_lock: str = "detection_rules/etc/version.lock.json",
    deprecated_file: str = "detection_rules/etc/deprecated_rules.json",
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """Loads version and deprecated lock files from git tag."""
    import json

    git = utils.make_git()

    exists_args = ["ls-remote"]
    if remote:
        exists_args.append(remote)
    exists_args.append(f"refs/tags/{tag}")

    if not git(*exists_args):
        raise ValueError(f"tag: {tag} does not exist in {remote or 'local'}")

    fetch_tags = ["fetch"]
    if remote:
        fetch_tags += [remote, "--tags", "-f", tag]
    else:
        fetch_tags += ["--tags", "-f", tag]

    _ = git(*fetch_tags)

    commit_hash = git("rev-list", "-1", tag)
    try:
        version = json.loads(git("show", f"{tag}:{version_lock}"))
    except CalledProcessError:
        # Adding resiliency to account for the old directory structure
        version = json.loads(git("show", f"{tag}:etc/version.lock.json"))

    try:
        deprecated = json.loads(git("show", f"{tag}:{deprecated_file}"))
    except CalledProcessError:
        # Adding resiliency to account for the old directory structure
        deprecated = json.loads(git("show", f"{tag}:etc/deprecated_rules.json"))
    return commit_hash, version, deprecated


def update_metadata_from_file(rule_path: Path, fields_to_update: dict[str, Any]) -> dict[str, Any]:
    """Update metadata fields for a rule with local contents."""

    contents: dict[str, Any] = {}
    if not rule_path.exists():
        return contents

    rule_contents = RuleCollection().load_file(rule_path).contents

    if not isinstance(rule_contents, TOMLRuleContents):
        raise TypeError("TOML rule expected")

    local_metadata = rule_contents.metadata.to_dict()
    if local_metadata:
        contents["maturity"] = local_metadata.get("maturity", "development")
        for field_name, should_update in fields_to_update.items():
            if should_update and field_name in local_metadata:
                contents[field_name] = local_metadata[field_name]
    return contents


@dataclass
class BaseCollection[T]:
    """Base class for collections."""

    rules: list[T]

    def __len__(self) -> int:
        """Get the total amount of rules in the collection."""
        return len(self.rules)

    def __iter__(self) -> Iterator[T]:
        """Iterate over all rules in the collection."""
        return iter(self.rules)


@dataclass
class DeprecatedCollection(BaseCollection[DeprecatedRule]):
    """Collection of loaded deprecated rule dicts."""

    id_map: dict[str, DeprecatedRule] = field(default_factory=dict)  # type: ignore[reportUnknownVariableType]
    file_map: dict[Path, DeprecatedRule] = field(default_factory=dict)  # type: ignore[reportUnknownVariableType]
    name_map: dict[str, DeprecatedRule] = field(default_factory=dict)  # type: ignore[reportUnknownVariableType]
    rules: list[DeprecatedRule] = field(default_factory=list)  # type: ignore[reportUnknownVariableType]

    def __contains__(self, rule: DeprecatedRule) -> bool:
        """Check if a rule is in the map by comparing IDs."""
        return rule.id in self.id_map

    def filter(self, cb: Callable[[DeprecatedRule], bool]) -> "RuleCollection":
        """Retrieve a filtered collection of rules."""
        filtered_collection = RuleCollection()

        for rule in filter(cb, self.rules):
            filtered_collection.add_deprecated_rule(rule)

        return filtered_collection


class RawRuleCollection(BaseCollection[DictRule]):
    """Collection of rules in raw dict form."""

    __default = None
    __default_bbr = None

    def __init__(self, rules: list[DictRule] | None = None, ext_patterns: list[str] | None = None) -> None:
        """Create a new raw rule collection, with optional file ext pattern override."""
        # ndjson is unsupported since it breaks the contract of 1 rule per file, so rules should be manually broken out
        # first
        self.ext_patterns = ext_patterns or ["*.toml", "*.json"]
        self.id_map: dict[definitions.UUIDString, DictRule] = {}
        self.file_map: dict[Path, DictRule] = {}
        self.name_map: dict[definitions.RuleName, DictRule] = {}
        self.rules: list[DictRule] = []
        self.errors: dict[Path, Exception] = {}
        self.frozen = False

        self._raw_load_cache: dict[Path, dict[str, Any]] = {}
        for rule in rules or []:
            self.add_rule(rule)

    def __contains__(self, rule: DictRule) -> bool:
        """Check if a rule is in the map by comparing IDs."""
        return rule.id in self.id_map

    def filter(self, cb: Callable[[DictRule], bool]) -> "RawRuleCollection":
        """Retrieve a filtered collection of rules."""
        filtered_collection = RawRuleCollection()

        for rule in filter(cb, self.rules):
            filtered_collection.add_rule(rule)

        return filtered_collection

    def _load_rule_file(self, path: Path) -> dict[str, Any]:
        """Load a rule file into a dictionary."""
        if path in self._raw_load_cache:
            return self._raw_load_cache[path]

        if path.suffix == ".toml":
            # use pytoml instead of toml because of annoying bugs
            # https://github.com/uiri/toml/issues/152
            # might also be worth looking at https://github.com/sdispater/tomlkit
            raw_dict = pytoml.loads(path.read_text())  # type: ignore[reportUnknownMemberType]
        elif path.suffix == ".json":
            raw_dict = json.loads(path.read_text())
        elif path.suffix == ".ndjson":
            raise ValueError("ndjson is not supported in RawRuleCollection. Break out the rules individually.")
        else:
            raise ValueError(f"Unsupported file type {path.suffix} for rule {path}")

        self._raw_load_cache[path] = raw_dict
        return raw_dict  # type: ignore[reportUnknownVariableType]

    def _get_paths(self, directory: Path, recursive: bool = True) -> list[Path]:
        """Get all paths in a directory that match the ext patterns."""
        paths: list[Path] = []
        for pattern in self.ext_patterns:
            paths.extend(sorted(directory.rglob(pattern) if recursive else directory.glob(pattern)))
        return paths

    def _assert_new(self, rule: DictRule) -> None:
        """Assert that a rule is new and can be added to the collection."""
        id_map = self.id_map
        file_map = self.file_map
        name_map = self.name_map

        if self.frozen:
            raise ValueError(f"Unable to add rule {rule.name} {rule.id} to a frozen collection")

        if rule.id in id_map:
            raise ValueError(f"Rule ID {rule.id} for {rule.name} collides with rule {id_map[rule.id].name}")

        if rule.name in name_map:
            raise ValueError(f"Rule Name {rule.name} for {rule.id} collides with rule ID {name_map[rule.name].id}")

        if rule.path is not None:
            rule_path = rule.path.resolve()
            if rule_path in file_map:
                raise ValueError(f"Rule file {rule_path} already loaded")
            file_map[rule_path] = rule

    def add_rule(self, rule: DictRule) -> None:
        """Add a rule to the collection."""
        self._assert_new(rule)
        self.id_map[rule.id] = rule
        self.name_map[rule.name] = rule
        self.rules.append(rule)

    def load_dict(self, obj: dict[str, Any], path: Path | None = None) -> DictRule:
        """Load a rule from a dictionary."""
        rule = DictRule(contents=obj, path=path)
        self.add_rule(rule)
        return rule

    def load_file(self, path: Path) -> DictRule:
        """Load a rule from a file."""
        try:
            path = path.resolve()
            # use the default rule loader as a cache.
            # if it already loaded the rule, then we can just use it from that
            if self.__default and self is not self.__default and path in self.__default.file_map:
                rule = self.__default.file_map[path]
                self.add_rule(rule)
                return rule

            obj = self._load_rule_file(path)
            return self.load_dict(obj, path=path)
        except Exception:
            print(f"Error loading rule in {path}")
            raise

    def load_files(self, paths: Iterable[Path]) -> None:
        """Load multiple files into the collection."""
        for path in paths:
            _ = self.load_file(path)

    def load_directory(
        self,
        directory: Path,
        recursive: bool = True,
        obj_filter: Callable[..., bool] | None = None,
    ) -> None:
        """Load all rules in a directory."""
        paths = self._get_paths(directory, recursive=recursive)
        if obj_filter is not None:
            paths = [path for path in paths if obj_filter(self._load_rule_file(path))]

        self.load_files(paths)

    def load_directories(
        self,
        directories: Iterable[Path],
        recursive: bool = True,
        obj_filter: Callable[..., bool] | None = None,
    ) -> None:
        """Load all rules in multiple directories."""
        for path in directories:
            self.load_directory(path, recursive=recursive, obj_filter=obj_filter)

    def freeze(self) -> None:
        """Freeze the rule collection and make it immutable going forward."""
        self.frozen = True

    @classmethod
    def default(cls) -> "RawRuleCollection":
        """Return the default rule collection, which retrieves from rules/."""
        if cls.__default is None:
            collection = RawRuleCollection()
            collection.load_directories(DEFAULT_PREBUILT_RULES_DIRS)
            collection.load_directories(DEFAULT_PREBUILT_BBR_DIRS)
            collection.freeze()
            cls.__default = collection

        return cls.__default

    @classmethod
    def default_bbr(cls) -> "RawRuleCollection":
        """Return the default BBR collection, which retrieves from building_block_rules/."""
        if cls.__default_bbr is None:
            collection = RawRuleCollection()
            collection.load_directories(DEFAULT_PREBUILT_BBR_DIRS)
            collection.freeze()
            cls.__default_bbr = collection

        return cls.__default_bbr


class RuleCollection(BaseCollection[TOMLRule]):
    """Collection of rule objects."""

    __default = None
    __default_bbr = None

    def __init__(self, rules: list[TOMLRule] | None = None) -> None:
        self.id_map: dict[definitions.UUIDString, TOMLRule] = {}
        self.file_map: dict[Path, TOMLRule] = {}
        self.name_map: dict[definitions.RuleName, TOMLRule] = {}
        self.rules: list[TOMLRule] = []
        self.deprecated: DeprecatedCollection = DeprecatedCollection()
        self.errors: dict[Path, Exception] = {}
        self.frozen = False

        self._toml_load_cache: dict[Path, dict[str, Any]] = {}
        self._version_lock: VersionLock | None = None

        for rule in rules or []:
            self.add_rule(rule)

    def __contains__(self, rule: TOMLRule) -> bool:
        """Check if a rule is in the map by comparing IDs."""
        return rule.id in self.id_map

    def filter(self, cb: Callable[[TOMLRule], bool]) -> "RuleCollection":
        """Retrieve a filtered collection of rules."""
        filtered_collection = RuleCollection()

        for rule in filter(cb, self.rules):
            filtered_collection.add_rule(rule)

        return filtered_collection

    @staticmethod
    def deserialize_toml_string(contents: bytes | str) -> dict[str, Any]:
        return pytoml.loads(contents)  # type: ignore[reportUnknownMemberType]

    def _load_toml_file(self, path: Path) -> dict[str, Any]:
        if path in self._toml_load_cache:
            return self._toml_load_cache[path]

        # use pytoml instead of toml because of annoying bugs
        # https://github.com/uiri/toml/issues/152
        # might also be worth looking at https://github.com/sdispater/tomlkit
        with path.open("r", encoding="utf-8") as f:
            toml_dict = self.deserialize_toml_string(f.read())
            self._toml_load_cache[path] = toml_dict
            return toml_dict

    def _get_paths(self, directory: Path, recursive: bool = True) -> list[Path]:
        return sorted(directory.rglob("*.toml") if recursive else directory.glob("*.toml"))

    def _assert_new(self, rule: TOMLRule | DeprecatedRule, is_deprecated: bool = False) -> None:
        if is_deprecated:
            id_map = self.deprecated.id_map
            file_map = self.deprecated.file_map
            name_map = self.deprecated.name_map
        else:
            id_map = self.id_map
            file_map = self.file_map
            name_map = self.name_map

        if not rule.id:
            raise ValueError("Rule has no ID")

        if self.frozen:
            raise ValueError(f"Unable to add rule {rule.name} {rule.id} to a frozen collection")

        if rule.id in id_map:
            raise ValueError(f"Rule ID {rule.id} for {rule.name} collides with rule {id_map[rule.id].name}")

        if not rule.name:
            raise ValueError("Rule has no name")

        if rule.name in name_map:
            raise ValueError(f"Rule Name {rule.name} for {rule.id} collides with rule ID {name_map[rule.name].id}")

        if rule.path is not None:
            rule_path = rule.path.resolve()
            if rule_path in file_map:
                raise ValueError(f"Rule file {rule_path} already loaded")
            file_map[rule_path] = rule  # type: ignore[reportArgumentType]

    def add_rule(self, rule: TOMLRule) -> None:
        self._assert_new(rule)
        self.id_map[rule.id] = rule
        self.name_map[rule.name] = rule
        self.rules.append(rule)

    def add_deprecated_rule(self, rule: DeprecatedRule) -> None:
        self._assert_new(rule, is_deprecated=True)

        if not rule.id:
            raise ValueError("Rule has no ID")
        if not rule.name:
            raise ValueError("Rule has no name")

        self.deprecated.id_map[rule.id] = rule
        self.deprecated.name_map[rule.name] = rule
        self.deprecated.rules.append(rule)

    def load_dict(self, obj: dict[str, Any], path: Path | None = None) -> TOMLRule | DeprecatedRule:
        # bypass rule object load (load_dict) and load as a dict only
        if obj.get("metadata", {}).get("maturity", "") == "deprecated":
            contents = DeprecatedRuleContents.from_dict(obj)
            if not RULES_CONFIG.bypass_version_lock:
                contents.set_version_lock(self._version_lock)
            if not path:
                raise ValueError("No path value provided")
            deprecated_rule = DeprecatedRule(path, contents)
            self.add_deprecated_rule(deprecated_rule)
            return deprecated_rule
        contents = TOMLRuleContents.from_dict(obj)
        if not RULES_CONFIG.bypass_version_lock:
            contents.set_version_lock(self._version_lock)
        rule = TOMLRule(path=path, contents=contents)
        self.add_rule(rule)
        return rule

    def load_file(self, path: Path) -> TOMLRule | DeprecatedRule:
        try:
            path = path.resolve()

            # use the default rule loader as a cache.
            # if it already loaded the rule, then we can just use it from that
            if self.__default is not None and self is not self.__default:
                if path in self.__default.file_map:
                    rule = self.__default.file_map[path]
                    self.add_rule(rule)
                    return rule
                if path in self.__default.deprecated.file_map:
                    deprecated_rule = self.__default.deprecated.file_map[path]
                    self.add_deprecated_rule(deprecated_rule)
                    return deprecated_rule

            obj = self._load_toml_file(path)
            return self.load_dict(obj, path=path)
        except Exception:
            print(f"Error loading rule in {path}")
            raise

    def load_git_tag(self, branch: str, remote: str, skip_query_validation: bool = False) -> None:
        """Load rules from a Git branch."""
        from .version_lock import VersionLock, add_rule_types_to_lock

        git = utils.make_git()
        paths: list[str] = []
        for rules_dir in DEFAULT_PREBUILT_RULES_DIRS:
            rdir = rules_dir.relative_to(get_path(["."]))
            git_output = git("ls-tree", "-r", "--name-only", branch, rdir)
            paths.extend(git_output.splitlines())

        rule_contents: list[tuple[dict[str, Any], Path]] = []
        rule_map: dict[str, Any] = {}
        for path in paths:
            ppath = Path(path)
            if ppath.suffix != ".toml":
                continue

            contents = git("show", f"{branch}:{ppath}")
            toml_dict = self.deserialize_toml_string(contents)

            if skip_query_validation:
                toml_dict["metadata"]["query_schema_validation"] = False

            rule_contents.append((toml_dict, ppath))
            rule_map[toml_dict["rule"]["rule_id"]] = toml_dict

        commit_hash, v_lock, d_lock = load_locks_from_tag(remote, branch)

        v_lock_name_prefix = f"{remote}/" if remote else ""
        v_lock_name = f"{v_lock_name_prefix}{branch}-{commit_hash}"

        # For backwards compatibility with tagged branches that existed before the types were added and validation
        # enforced, we will need to manually add the rule types to the version lock allow them to pass validation.
        v_lock = add_rule_types_to_lock(v_lock, rule_map)

        version_lock = VersionLock(version_lock=v_lock, deprecated_lock=d_lock, name=v_lock_name)
        self._version_lock = version_lock

        for rule_content in rule_contents:
            toml_dict, path = rule_content
            try:
                _ = self.load_dict(toml_dict, path)
            except ValidationError as e:
                self.errors[path] = e
                continue

    def load_files(self, paths: Iterable[Path]) -> None:
        """Load multiple files into the collection."""
        for path in paths:
            _ = self.load_file(path)

    def load_directory(
        self,
        directory: Path,
        recursive: bool = True,
        obj_filter: Callable[..., bool] | None = None,
    ) -> None:
        paths = self._get_paths(directory, recursive=recursive)
        if obj_filter is not None:
            paths = [path for path in paths if obj_filter(self._load_toml_file(path))]

        self.load_files(paths)

    def load_directories(
        self,
        directories: Iterable[Path],
        recursive: bool = True,
        obj_filter: Callable[..., bool] | None = None,
    ) -> None:
        for path in directories:
            self.load_directory(path, recursive=recursive, obj_filter=obj_filter)

    def freeze(self) -> None:
        """Freeze the rule collection and make it immutable going forward."""
        self.frozen = True

    @classmethod
    def default(cls) -> "RuleCollection":
        """Return the default rule collection, which retrieves from rules/."""
        if cls.__default is None:
            collection = RuleCollection()
            collection.load_directories(DEFAULT_PREBUILT_RULES_DIRS)
            collection.load_directories(DEFAULT_PREBUILT_BBR_DIRS)
            collection.freeze()
            cls.__default = collection

        return cls.__default

    @classmethod
    def default_bbr(cls) -> "RuleCollection":
        """Return the default BBR collection, which retrieves from building_block_rules/."""
        if cls.__default_bbr is None:
            collection = RuleCollection()
            collection.load_directories(DEFAULT_PREBUILT_BBR_DIRS)
            collection.freeze()
            cls.__default_bbr = collection

        return cls.__default_bbr

    def compare_collections(
        self, other: "RuleCollection"
    ) -> tuple[dict[str, TOMLRule], dict[str, TOMLRule], dict[str, DeprecatedRule]]:
        """Get the changes between two sets of rules."""
        if not self._version_lock:
            raise ValueError("RuleCollection._version_lock must be set for self")

        if not other._version_lock:  # noqa: SLF001
            raise ValueError("RuleCollection._version_lock must be set for other")

        # we cannot trust the assumption that either of the versions or deprecated files were pre-locked, which means we
        # have to perform additional checks beyond what is done in manage_versions
        changed_rules: dict[str, TOMLRule] = {}
        new_rules: dict[str, TOMLRule] = {}
        newly_deprecated: dict[str, DeprecatedRule] = {}

        pre_versions_hash = utils.dict_hash(self._version_lock.version_lock.to_dict())
        post_versions_hash = utils.dict_hash(other._version_lock.version_lock.to_dict())  # noqa: SLF001
        pre_deprecated_hash = utils.dict_hash(self._version_lock.deprecated_lock.to_dict())
        post_deprecated_hash = utils.dict_hash(other._version_lock.deprecated_lock.to_dict())  # noqa: SLF001

        if pre_versions_hash == post_versions_hash and pre_deprecated_hash == post_deprecated_hash:
            return changed_rules, new_rules, newly_deprecated

        for rule in other:
            if rule.contents.metadata.maturity != "production":
                continue

            if rule.id not in self.id_map:
                new_rules[rule.id] = rule
            else:
                pre_rule = self.id_map[rule.id]
                if rule.contents.get_hash() != pre_rule.contents.get_hash():
                    changed_rules[rule.id] = rule

        for rule in other.deprecated:
            if rule.id and rule.id not in self.deprecated.id_map:
                newly_deprecated[rule.id] = rule

        return changed_rules, new_rules, newly_deprecated


@cached
def load_github_pr_rules(
    labels: list[str] | None = None,
    repo_name: str = "elastic/detection-rules",
    token: str | None = None,
    threads: int = 50,
    verbose: bool = True,
) -> tuple[dict[str, TOMLRule], dict[str, list[TOMLRule]], dict[str, list[str]]]:
    """Load all rules active as a GitHub PR."""

    github = GithubClient(token=token)
    repo = github.client.get_repo(repo_name)
    labels_set = set(labels or [])
    open_prs = [r for r in repo.get_pulls() if not labels_set.difference({lbl.name for lbl in r.get_labels()})]

    new_rules: list[TOMLRule] = []
    modified_rules: list[TOMLRule] = []
    errors: dict[str, list[str]] = {}

    existing_rules = RuleCollection.default()
    pr_rules: list[tuple[PullRequest, File]] = []

    if verbose:
        click.echo("Downloading rules from GitHub PRs")

    def download_worker(pr_info: tuple[PullRequest, File]) -> None:
        pull, rule_file = pr_info
        response = requests.get(rule_file.raw_url, timeout=10)
        try:
            raw_rule = pytoml.loads(response.text)  # type: ignore[reportUnknownVariableType]
            contents = TOMLRuleContents.from_dict(raw_rule)  # type: ignore[reportUnknownArgumentType]
            rule = TOMLRule(path=Path(rule_file.filename), contents=contents)
            rule.gh_pr = pull

            if rule in existing_rules:
                modified_rules.append(rule)
            else:
                new_rules.append(rule)

        except Exception as e:  # noqa: BLE001
            name = Path(rule_file.filename).name
            errors.setdefault(name, []).append(str(e))

    for pr in open_prs:
        pr_rules.extend(
            [(pr, f) for f in pr.get_files() if f.filename.startswith("rules/") and f.filename.endswith(".toml")]
        )

    pool = ThreadPool(processes=threads)
    _ = pool.map(download_worker, pr_rules)
    pool.close()
    pool.join()

    new = OrderedDict([(rule.contents.id, rule) for rule in sorted(new_rules, key=lambda r: r.contents.name)])
    modified: OrderedDict[str, list[TOMLRule]] = OrderedDict()

    for modified_rule in sorted(modified_rules, key=lambda r: r.contents.name):
        modified.setdefault(modified_rule.contents.id, []).append(modified_rule)

    return new, modified, errors


__all__ = (
    "DEFAULT_PREBUILT_BBR_DIRS",
    "DEFAULT_PREBUILT_RULES_DIRS",
    "FILE_PATTERN",
    "DeprecatedCollection",
    "DeprecatedRule",
    "RawRuleCollection",
    "RuleCollection",
    "dict_filter",
    "load_github_pr_rules",
    "metadata_filter",
    "production_filter",
)

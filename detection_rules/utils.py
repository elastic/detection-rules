# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Util functions."""

import base64
import contextlib
import functools
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import zipfile
from collections.abc import Callable, Iterator
from dataclasses import astuple, is_dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from string import Template
from typing import Any

import click
import eql.utils  # type: ignore[reportMissingTypeStubs]
import pytoml  # type: ignore[reportMissingTypeStubs]
from eql.utils import load_dump  # type: ignore[reportMissingTypeStubs]
from github.Repository import Repository

CURR_DIR = Path(__file__).resolve().parent
ROOT_DIR = CURR_DIR.parent
ETC_DIR = ROOT_DIR / "detection_rules" / "etc"
INTEGRATION_RULE_DIR = ROOT_DIR / "rules" / "integrations"
CUSTOM_RULES_KQL = 'alert.attributes.params.ruleSource.type: "internal" or alert.attributes.params.immutable: false'


class DateTimeEncoder(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if isinstance(o, (date | datetime)):
            return o.isoformat()
        return None


marshmallow_schemas = {}


def gopath() -> str | None:
    """Retrieve $GOPATH"""

    env_path = os.getenv("GOPATH")
    if env_path:
        return env_path

    go_bin = shutil.which("go")
    if go_bin:
        output = subprocess.check_output([go_bin, "env"], encoding="utf-8").splitlines()
        for line in output:
            if line.startswith("GOPATH="):
                return line[len("GOPATH=") :].strip('"')
    return None


def dict_hash(obj: dict[Any, Any]) -> str:
    """Hash a dictionary deterministically."""
    raw_bytes = base64.b64encode(json.dumps(obj, sort_keys=True).encode("utf-8"))
    return hashlib.sha256(raw_bytes).hexdigest()


def ensure_list_of_strings(value: str | list[str]) -> list[str]:
    """Ensure or convert a value is a list of strings."""
    if isinstance(value, str):
        # Check if the string looks like a JSON list
        if value.startswith("[") and value.endswith("]"):
            try:
                # Attempt to parse the string as a JSON list
                parsed_value = json.loads(value)
                if isinstance(parsed_value, list):
                    return [str(v) for v in parsed_value]  # type: ignore[reportUnknownVariableType]
            except json.JSONDecodeError:
                pass
        # If it's not a JSON list, split by commas if present
        # Else return a list with the original string
        return [x.strip().strip('"') for x in value.split(",")]
    return [str(v) for v in value]


def get_nested_value(obj: Any, compound_key: str) -> Any:
    """Get a nested value from a obj."""
    keys = compound_key.split(".")
    for key in keys:
        if isinstance(obj, dict):
            obj = obj.get(key)  # type: ignore[reportUnknownVariableType]
        else:
            return None
    return obj  # type: ignore[reportUnknownVariableType]


def get_path(paths: list[str]) -> Path:
    """Get a file by relative path."""
    return ROOT_DIR.joinpath(*paths)


def get_etc_path(paths: list[str]) -> Path:
    """Load a file from the detection_rules/etc/ folder."""
    return ETC_DIR.joinpath(*paths)


def get_etc_glob_path(patterns: list[str]) -> list[Path]:
    """Load a file from the detection_rules/etc/ folder."""
    pattern = os.path.join(*patterns)  # noqa: PTH118
    return list(ETC_DIR.glob(pattern))


def get_etc_file(name: str, mode: str = "r") -> str:
    """Load a file from the detection_rules/etc/ folder."""
    with get_etc_path([name]).open(mode) as f:
        return f.read()


def load_etc_dump(paths: list[str]) -> Any:
    """Load a json/yml/toml file from the detection_rules/etc/ folder."""
    return eql.utils.load_dump(str(get_etc_path(paths)))  # type: ignore[reportUnknownVariableType]


def save_etc_dump(contents: dict[str, Any], path: list[str], sort_keys: bool = True, indent: int = 2) -> None:
    """Save a json/yml/toml file from the detection_rules/etc/ folder."""
    path_joined = get_etc_path(path)

    if path_joined.suffix == ".json":
        with path_joined.open("w") as f:
            json.dump(contents, f, cls=DateTimeEncoder, sort_keys=sort_keys, indent=indent)
    else:
        eql.utils.save_dump(contents, path)  # type: ignore[reportUnknownVariableType]


def set_all_validation_bypass(env_value: bool = False) -> None:
    """Set all validation bypass environment variables."""
    os.environ["DR_BYPASS_NOTE_VALIDATION_AND_PARSE"] = str(env_value)
    os.environ["DR_BYPASS_BBR_LOOKBACK_VALIDATION"] = str(env_value)
    os.environ["DR_BYPASS_TAGS_VALIDATION"] = str(env_value)
    os.environ["DR_BYPASS_TIMELINE_TEMPLATE_VALIDATION"] = str(env_value)


def set_nested_value(obj: dict[str, Any], compound_key: str, value: Any) -> None:
    """Set a nested value in a obj."""
    keys = compound_key.split(".")
    for key in keys[:-1]:
        obj = obj.setdefault(key, {})
    obj[keys[-1]] = value


def gzip_compress(contents: str) -> bytes:
    gz_file = io.BytesIO()

    with gzip.GzipFile(mode="w", fileobj=gz_file) as f:
        encoded = contents if isinstance(contents, bytes) else contents.encode("utf8")
        _ = f.write(encoded)

    return gz_file.getvalue()


def read_gzip(path: str | Path) -> str:
    with gzip.GzipFile(str(path), mode="r") as gz:
        return gz.read().decode("utf8")


@contextlib.contextmanager
def unzip(contents: bytes) -> Iterator[zipfile.ZipFile]:
    """Get zipped contents."""
    zipped = io.BytesIO(contents)
    archive = zipfile.ZipFile(zipped, mode="r")

    try:
        yield archive
    finally:
        archive.close()


def unzip_and_save(contents: bytes, path: str, member: str | None = None, verbose: bool = True) -> None:
    """Save unzipped from raw zipped contents."""
    with unzip(contents) as archive:
        if member:
            _ = archive.extract(member, path)
        else:
            archive.extractall(path)

        if verbose:
            name_list = archive.namelist()
            print("Saved files to {}: \n\t- {}".format(path, "\n\t- ".join(name_list)))


def unzip_to_dict(zipped: zipfile.ZipFile, load_json: bool = True) -> dict[str, Any]:
    """Unzip and load contents to dict with filenames as keys."""
    bundle: dict[str, Any] = {}
    for filename in zipped.namelist():
        if filename.endswith("/"):
            continue

        fp = Path(filename)
        contents = zipped.read(filename)

        if load_json and fp.suffix == ".json":
            contents = json.loads(contents)

        bundle[fp.name] = contents

    return bundle


def event_sort(
    events: list[Any],
    timestamp: str = "@timestamp",
    date_format: str = "%Y-%m-%dT%H:%M:%S.%f%z",
    order_asc: bool = True,
) -> list[Any]:
    """Sort events from elasticsearch by timestamp."""

    def round_microseconds(t: str) -> str:
        """Rounds the microseconds part of a timestamp string to 6 decimal places."""

        if not t:
            # Return early if the timestamp string is empty
            return t

        parts = t.split(".")
        if len(parts) == 2:  # noqa: PLR2004
            # Remove trailing "Z" from microseconds part
            micro_seconds = parts[1].rstrip("Z")

            if len(micro_seconds) > 6:  # noqa: PLR2004
                # If the microseconds part has more than 6 digits
                # Convert the microseconds part to a float and round to 6 decimal places
                rounded_micro_seconds = round(float(f"0.{micro_seconds}"), 6)

                # Format the rounded value to always have 6 decimal places
                # Reconstruct the timestamp string with the rounded microseconds part
                formatted_micro_seconds = f"{rounded_micro_seconds:0.6f}".split(".")[-1]
                t = f"{parts[0]}.{formatted_micro_seconds}Z"

        return t

    def _event_sort(event: dict[str, Any]) -> datetime:
        """Calculates the sort key for an event as a datetime object."""
        t = round_microseconds(event[timestamp])

        # Return the timestamp as a datetime object for comparison
        return datetime.strptime(t, date_format)  # noqa: DTZ007

    return sorted(events, key=_event_sort, reverse=not order_asc)


def convert_time_span(span: str) -> int:
    """Convert time span in Date Math to value in milliseconds."""
    amount = int("".join(char for char in span if char.isdigit()))
    unit = eql.ast.TimeUnit("".join(char for char in span if char.isalpha()))
    return eql.ast.TimeRange(amount, unit).as_milliseconds()


def unix_time_to_formatted(timestamp: float | str) -> str:
    """Converts unix time in seconds or milliseconds to the default format."""
    if isinstance(timestamp, (int | float)):
        if timestamp > 2**32:
            timestamp = round(timestamp / 1000, 3)

        return datetime.fromtimestamp(timestamp, UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return timestamp


def normalize_timing_and_sort(
    events: list[dict[str, Any]],
    timestamp: str = "@timestamp",
    order_asc: bool = True,
) -> list[Any]:
    """Normalize timestamp formats and sort events."""
    for event in events:
        _timestamp = event[timestamp]
        if not isinstance(_timestamp, str):
            event[timestamp] = unix_time_to_formatted(_timestamp)

    return event_sort(events, timestamp=timestamp, order_asc=order_asc)


def freeze(obj: Any) -> Any:
    """Helper function to make mutable objects immutable and hashable."""
    if not isinstance(obj, type) and is_dataclass(obj):
        obj = astuple(obj)  # type: ignore[reportUnknownVariableType]

    if isinstance(obj, (list | tuple)):
        return tuple(freeze(o) for o in obj)  # type: ignore[reportUnknownVariableType]
    if isinstance(obj, dict):
        items = obj.items()  # type: ignore[reportUnknownVariableType]
        return freeze(sorted(items))  # type: ignore[reportUnknownVariableType]
    return obj


_cache: dict[int, dict[tuple[Any, Any], Any]] = {}


# Should be replaced with `functools.cache`
# https://docs.python.org/3/library/functools.html#functools.cache
def cached(f: Callable[..., Any]) -> Callable[..., Any]:
    """Helper function to memoize functions."""
    func_key = id(f)

    @functools.wraps(f)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        _ = _cache.setdefault(func_key, {})
        cache_key = freeze(args), freeze(kwargs)

        if cache_key not in _cache[func_key]:
            _cache[func_key][cache_key] = f(*args, **kwargs)

        return _cache[func_key][cache_key]

    def clear() -> None:
        _ = _cache.pop(func_key, None)

    wrapped.clear = clear  # type: ignore[reportAttributeAccessIssue]
    return wrapped


def clear_caches() -> None:
    _cache.clear()


def rulename_to_filename(name: str, tactic_name: str | None = None, ext: str = ".toml") -> str:
    """Convert a rule name to a filename."""
    name = re.sub(r"[^_a-z0-9]+", "_", name.strip().lower()).strip("_")
    if tactic_name:
        pre = rulename_to_filename(name=tactic_name, ext="")
        name = f"{pre}_{name}"
    return name + ext or ""


def load_rule_contents(rule_file: Path, single_only: bool = False) -> list[Any]:
    """Load a rule file from multiple formats."""
    extension = rule_file.suffix
    raw_text = rule_file.read_text()

    if extension in (".ndjson", ".jsonl"):
        # kibana exported rule object is ndjson with the export metadata on the last line
        contents = [json.loads(line) for line in raw_text.splitlines()]

        if len(contents) > 1 and "exported_count" in contents[-1]:
            contents.pop(-1)

        if single_only and len(contents) > 1:
            raise ValueError("Multiple rules not allowed")

        return contents or [{}]
    if extension == ".toml":
        rule = pytoml.loads(raw_text)  # type: ignore[reportUnknownVariableType]
    elif extension.lower() in ("yaml", "yml"):
        rule = load_dump(str(rule_file))
    else:
        return []

    if isinstance(rule, dict):
        return [rule]
    if isinstance(rule, list):
        return rule  # type: ignore[reportUnknownVariableType]
    raise ValueError(f"Expected a list or dictionary in {rule_file}")


def load_json_from_branch(repo: Repository, file_path: str, branch: str) -> dict[str, Any]:
    """Load JSON file from a specific branch."""
    content_files = repo.get_contents(file_path, ref=branch)

    if isinstance(content_files, list):
        raise ValueError("Receive a list instead of a single value")  # noqa: TRY004

    content_file = content_files
    content = content_file.decoded_content
    data = content.decode("utf-8")
    return json.loads(data)


def compare_versions(base_json: dict[str, Any], branch_json: dict[str, Any]) -> list[tuple[str, str, int, int]]:
    """Compare versions of two lock version file JSON objects."""
    changes: list[tuple[str, str, int, int]] = []
    for key, base_val in base_json.items():
        if key in branch_json:
            base_version = base_val.get("version")
            branch_name = branch_json[key].get("rule_name")
            branch_version = branch_json[key].get("version")
            if base_version != branch_version:
                changes.append((key, branch_name, base_version, branch_version))
    return changes


def check_double_bumps(changes: list[tuple[str, str, int, int]]) -> list[tuple[str, str, int, int]]:
    """Check for double bumps in version changes of the result of compare versions of a version lock file."""
    double_bumps: list[tuple[str, str, int, int]] = []
    for key, name, removed, added in changes:
        # Determine the modulo dynamically based on the highest number of digits
        max_digits = max(len(str(removed)), len(str(added)))
        modulo = max(10 ** (max_digits - 1), 100)
        if (added % modulo) - (removed % modulo) > 1:
            double_bumps.append((key, name, removed, added))
    return double_bumps


def check_version_lock_double_bumps(
    repo: Repository,
    file_path: str,
    base_branch: str,
    branch: str = "",
    local_file: Path | None = None,
) -> list[tuple[str, str, int, int]]:
    """Check for double bumps in version changes of the result of compare versions of a version lock file."""
    base_json = load_json_from_branch(repo, file_path, base_branch)
    if local_file:
        with local_file.open("r") as f:
            branch_json = json.load(f)
    else:
        branch_json = load_json_from_branch(repo, file_path, branch)

    changes = compare_versions(base_json, branch_json)
    return check_double_bumps(changes)


def format_command_options(ctx: click.Context) -> str:
    """Echo options for a click command."""
    formatter = ctx.make_formatter()
    opts: list[tuple[str, str]] = []

    for param in ctx.command.get_params(ctx):
        if param.name == "help":
            continue

        rv = param.get_help_record(ctx)
        if rv is not None:
            opts.append(rv)

    if opts:
        with formatter.section("Options"):
            formatter.write_dl(opts)

    return formatter.getvalue()


def make_git(*prefix_args: Any) -> Callable[..., str]:
    git_exe = shutil.which("git")
    prefix_arg_strs = [str(arg) for arg in prefix_args]

    if "-C" not in prefix_arg_strs:
        prefix_arg_strs = ["-C", str(ROOT_DIR), *prefix_arg_strs]

    if not git_exe:
        click.secho("Unable to find git", err=True, fg="red")
        ctx = click.get_current_context(silent=True)

        if ctx is not None:
            ctx.exit(1)

        raise ValueError("Git not found")

    def git(*args: Any) -> str:
        arg_strs = [str(arg) for arg in args]
        full_args = [git_exe, *prefix_arg_strs, *arg_strs]
        return subprocess.check_output(full_args, encoding="utf-8").rstrip()

    return git


def git(*args: Any, **kwargs: Any) -> str | int:
    """Find and run a one-off Git command."""
    g = make_git()
    return g(*args, **kwargs)


FuncT = Callable[..., Any]


def add_params(*params: Any) -> Callable[[FuncT], FuncT]:
    """Add parameters to a click command."""

    def decorator(f: FuncT) -> FuncT:
        if not hasattr(f, "__click_params__"):
            f.__click_params__ = []  # type: ignore[reportFunctionMemberAccess]
        f.__click_params__.extend(params)  # type: ignore[reportFunctionMemberAccess]
        return f

    return decorator


class Ndjson(list[dict[str, Any]]):
    """Wrapper for ndjson data."""

    def to_string(self, sort_keys: bool = False) -> str:
        """Format contents list to ndjson string."""
        return "\n".join(json.dumps(c, sort_keys=sort_keys) for c in self) + "\n"

    @classmethod
    def from_string(cls, ndjson_string: str, **kwargs: Any) -> "Ndjson":
        """Load ndjson string to a list."""
        contents = [json.loads(line, **kwargs) for line in ndjson_string.strip().splitlines()]
        return Ndjson(contents)

    def dump(self, filename: Path, sort_keys: bool = False) -> None:
        """Save contents to an ndjson file."""
        _ = filename.write_text(self.to_string(sort_keys=sort_keys))

    @classmethod
    def load(cls, filename: Path, **kwargs: Any) -> "Ndjson":
        """Load content from an ndjson file."""
        return cls.from_string(filename.read_text(), **kwargs)


class PatchedTemplate(Template):
    """String template with updated methods from future versions."""

    def get_identifiers(self) -> list[str]:
        """Returns a list of the valid identifiers in the template, in the order they first appear, ignoring any
        invalid identifiers."""
        # https://github.com/python/cpython/blob/3b4f8fc83dcea1a9d0bc5bd33592e5a3da41fa71/Lib/string.py#LL157-L171C19
        ids: list[str] = []
        for mo in self.pattern.finditer(self.template):
            named = mo.group("named") or mo.group("braced")
            if named and named not in ids:
                # add a named group only the first time it appears
                ids.append(named)
            elif not named and mo.group("invalid") is None and mo.group("escaped") is None:
                # If all the groups are None, there must be
                # another group we're not expecting
                raise ValueError("Unrecognized named group in pattern", self.pattern)
        return ids


def convert_to_nested_schema(flat_schemas: dict[str, str]) -> dict[str, Any]:
    """Convert a flat schema to a nested schema with 'properties' for each sub-key."""
    # NOTE this is needed to conform to Kibana's index mapping format
    nested_schema = {}

    for key, value in flat_schemas.items():
        parts = key.split(".")
        current_level = nested_schema

        for part in parts[:-1]:
            current_level = current_level.setdefault(part, {}).setdefault("properties", {})  # type: ignore[reportUnknownVariableType]

        current_level[parts[-1]] = {"type": value}

    return nested_schema  # type: ignore[reportUnknownVariableType]


def combine_dicts(dest: dict[Any, Any], src: dict[Any, Any]) -> None:
    """Combine two dictionaries recursively."""
    for k, v in src.items():
        if k in dest and isinstance(dest[k], dict) and isinstance(v, dict):
            combine_dicts(dest[k], v)  # type: ignore[reportUnknownVariableType]
        else:
            dest[k] = v


def get_column_from_index_mapping_schema(keys: list[str], current_schema: dict[str, Any] | None) -> str | None:
    """Recursively traverse the schema to find the type of the column."""
    key = keys[0]
    if not current_schema:
        return None
    column = current_schema.get(key) or {}  # type: ignore[reportUnknownVariableType]
    column_type = column.get("type") if column else None  # type: ignore[reportUnknownVariableType]
    if len(keys) > 1:
        return get_column_from_index_mapping_schema(keys[1:], current_schema=column.get("properties"))  # type: ignore[reportUnknownVariableType]
    return column_type  # type: ignore[reportUnknownVariableType]

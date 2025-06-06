# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Util functions."""
import base64
import contextlib
import functools
import glob
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import zipfile
from dataclasses import is_dataclass, astuple
from datetime import datetime, date, timezone
from pathlib import Path
from typing import Dict, Union, Optional, Callable
from string import Template

import click
import pytoml
import eql.utils
from eql.utils import load_dump, stream_json_lines
from github.Repository import Repository

import kql


CURR_DIR = Path(__file__).resolve().parent
ROOT_DIR = CURR_DIR.parent
ETC_DIR = ROOT_DIR / "detection_rules" / "etc"
INTEGRATION_RULE_DIR = ROOT_DIR / "rules" / "integrations"


class NonelessDict(dict):
    """Wrapper around dict that doesn't populate None values."""

    def __setitem__(self, key, value):
        if value is not None:
            dict.__setitem__(self, key, value)


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (date, datetime)):
            return obj.isoformat()


marshmallow_schemas = {}


def gopath() -> Optional[str]:
    """Retrieve $GOPATH."""
    env_path = os.getenv("GOPATH")
    if env_path:
        return env_path

    go_bin = shutil.which("go")
    if go_bin:
        output = subprocess.check_output([go_bin, "env"], encoding="utf-8").splitlines()
        for line in output:
            if line.startswith("GOPATH="):
                return line[len("GOPATH="):].strip('"')


def dict_hash(obj: dict) -> str:
    """Hash a dictionary deterministically."""
    raw_bytes = base64.b64encode(json.dumps(obj, sort_keys=True).encode('utf-8'))
    return hashlib.sha256(raw_bytes).hexdigest()


def ensure_list_of_strings(value: str | list) -> list[str]:
    """Ensure or convert a value is a list of strings."""
    if isinstance(value, str):
        # Check if the string looks like a JSON list
        if value.startswith('[') and value.endswith(']'):
            try:
                # Attempt to parse the string as a JSON list
                parsed_value = json.loads(value)
                if isinstance(parsed_value, list):
                    return [str(v) for v in parsed_value]
            except json.JSONDecodeError:
                pass
        # If it's not a JSON list, split by commas if present
        # Else return a list with the original string
        return list(map(lambda x: x.strip().strip('"'), value.split(',')))
    elif isinstance(value, list):
        return [str(v) for v in value]
    else:
        return []


def get_json_iter(f):
    """Get an iterator over a JSON file."""
    first = f.read(2)
    f.seek(0)

    if first[0] == '[' or first == "{\n":
        return json.load(f)
    else:
        data = list(stream_json_lines(f))
    return data


def get_nested_value(dictionary, compound_key):
    """Get a nested value from a dictionary."""
    keys = compound_key.split('.')
    for key in keys:
        if isinstance(dictionary, dict):
            dictionary = dictionary.get(key)
        else:
            return None
    return dictionary


def get_path(*paths) -> Path:
    """Get a file by relative path."""
    return ROOT_DIR.joinpath(*paths)


def get_etc_path(*paths) -> Path:
    """Load a file from the detection_rules/etc/ folder."""
    return ETC_DIR.joinpath(*paths)


def get_etc_glob_path(*patterns) -> list:
    """Load a file from the detection_rules/etc/ folder."""
    pattern = os.path.join(*patterns)
    return glob.glob(str(ETC_DIR / pattern))


def get_etc_file(name, mode="r"):
    """Load a file from the detection_rules/etc/ folder."""
    with open(get_etc_path(name), mode) as f:
        return f.read()


def load_etc_dump(*path):
    """Load a json/yml/toml file from the detection_rules/etc/ folder."""
    return eql.utils.load_dump(str(get_etc_path(*path)))


def save_etc_dump(contents, *path, **kwargs):
    """Save a json/yml/toml file from the detection_rules/etc/ folder."""
    path = str(get_etc_path(*path))
    _, ext = os.path.splitext(path)
    sort_keys = kwargs.pop('sort_keys', True)
    indent = kwargs.pop('indent', 2)

    if ext == ".json":
        with open(path, "wt") as f:
            json.dump(contents, f, cls=DateTimeEncoder, sort_keys=sort_keys, indent=indent, **kwargs)
    else:
        return eql.utils.save_dump(contents, path)


def set_all_validation_bypass(env_value: bool = False):
    """Set all validation bypass environment variables."""
    os.environ['DR_BYPASS_NOTE_VALIDATION_AND_PARSE'] = str(env_value)
    os.environ['DR_BYPASS_BBR_LOOKBACK_VALIDATION'] = str(env_value)
    os.environ['DR_BYPASS_TAGS_VALIDATION'] = str(env_value)
    os.environ['DR_BYPASS_TIMELINE_TEMPLATE_VALIDATION'] = str(env_value)


def set_nested_value(dictionary, compound_key, value):
    """Set a nested value in a dictionary."""
    keys = compound_key.split('.')
    for key in keys[:-1]:
        dictionary = dictionary.setdefault(key, {})
    dictionary[keys[-1]] = value


def gzip_compress(contents) -> bytes:
    gz_file = io.BytesIO()

    with gzip.GzipFile(mode="w", fileobj=gz_file) as f:
        if not isinstance(contents, bytes):
            contents = contents.encode("utf8")
        f.write(contents)

    return gz_file.getvalue()


def read_gzip(path):
    with gzip.GzipFile(path, mode='r') as gz:
        return gz.read().decode("utf8")


@contextlib.contextmanager
def unzip(contents):  # type: (bytes) -> zipfile.ZipFile
    """Get zipped contents."""
    zipped = io.BytesIO(contents)
    archive = zipfile.ZipFile(zipped, mode="r")

    try:
        yield archive

    finally:
        archive.close()


def unzip_and_save(contents, path, member=None, verbose=True):
    """Save unzipped from raw zipped contents."""
    with unzip(contents) as archive:

        if member:
            archive.extract(member, path)
        else:
            archive.extractall(path)

        if verbose:
            name_list = archive.namelist()[member] if not member else archive.namelist()
            print('Saved files to {}: \n\t- {}'.format(path, '\n\t- '.join(name_list)))


def unzip_to_dict(zipped: zipfile.ZipFile, load_json=True) -> Dict[str, Union[dict, str]]:
    """Unzip and load contents to dict with filenames as keys."""
    bundle = {}
    for filename in zipped.namelist():
        if filename.endswith('/'):
            continue

        fp = Path(filename)
        contents = zipped.read(filename)

        if load_json and fp.suffix == '.json':
            contents = json.loads(contents)

        bundle[fp.name] = contents

    return bundle


def event_sort(events, timestamp='@timestamp', date_format='%Y-%m-%dT%H:%M:%S.%f%z', asc=True):
    """Sort events from elasticsearch by timestamp."""

    def round_microseconds(t: str) -> str:
        """Rounds the microseconds part of a timestamp string to 6 decimal places."""

        if not t:
            # Return early if the timestamp string is empty
            return t

        parts = t.split('.')
        if len(parts) == 2:
            # Remove trailing "Z" from microseconds part
            micro_seconds = parts[1].rstrip("Z")

            if len(micro_seconds) > 6:
                # If the microseconds part has more than 6 digits
                # Convert the microseconds part to a float and round to 6 decimal places
                rounded_micro_seconds = round(float(f"0.{micro_seconds}"), 6)

                # Format the rounded value to always have 6 decimal places
                # Reconstruct the timestamp string with the rounded microseconds part
                formatted_micro_seconds = f'{rounded_micro_seconds:0.6f}'.split(".")[-1]
                t = f"{parts[0]}.{formatted_micro_seconds}Z"

        return t

    def _event_sort(event: dict) -> datetime:
        """Calculates the sort key for an event as a datetime object."""
        t = round_microseconds(event[timestamp])

        # Return the timestamp as a datetime object for comparison
        return datetime.strptime(t, date_format)

    return sorted(events, key=_event_sort, reverse=not asc)


def combine_sources(*sources):  # type: (list[list]) -> list
    """Combine lists of events from multiple sources."""
    combined = []
    for source in sources:
        combined.extend(source.copy())

    return event_sort(combined)


def convert_time_span(span: str) -> int:
    """Convert time span in Date Math to value in milliseconds."""
    amount = int("".join(char for char in span if char.isdigit()))
    unit = eql.ast.TimeUnit("".join(char for char in span if char.isalpha()))
    return eql.ast.TimeRange(amount, unit).as_milliseconds()


def evaluate(rule, events, normalize_kql_keywords: bool = False):
    """Evaluate a query against events."""
    evaluator = kql.get_evaluator(kql.parse(rule.query), normalize_kql_keywords=normalize_kql_keywords)
    filtered = list(filter(evaluator, events))
    return filtered


def unix_time_to_formatted(timestamp):  # type: (int|str) -> str
    """Converts unix time in seconds or milliseconds to the default format."""
    if isinstance(timestamp, (int, float)):
        if timestamp > 2 ** 32:
            timestamp = round(timestamp / 1000, 3)

        return datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def normalize_timing_and_sort(events, timestamp='@timestamp', asc=True):
    """Normalize timestamp formats and sort events."""
    for event in events:
        _timestamp = event[timestamp]
        if not isinstance(_timestamp, str):
            event[timestamp] = unix_time_to_formatted(_timestamp)

    return event_sort(events, timestamp=timestamp, asc=asc)


def freeze(obj):
    """Helper function to make mutable objects immutable and hashable."""
    if not isinstance(obj, type) and is_dataclass(obj):
        obj = astuple(obj)

    if isinstance(obj, (list, tuple)):
        return tuple(freeze(o) for o in obj)
    elif isinstance(obj, dict):
        return freeze(sorted(obj.items()))
    else:
        return obj


_cache = {}


def cached(f):
    """Helper function to memoize functions."""
    func_key = id(f)

    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        _cache.setdefault(func_key, {})
        cache_key = freeze(args), freeze(kwargs)

        if cache_key not in _cache[func_key]:
            _cache[func_key][cache_key] = f(*args, **kwargs)

        return _cache[func_key][cache_key]

    def clear():
        _cache.pop(func_key, None)

    wrapped.clear = clear
    return wrapped


def clear_caches():
    _cache.clear()


def rulename_to_filename(name: str, tactic_name: str = None, ext: str = '.toml') -> str:
    """Convert a rule name to a filename."""
    name = re.sub(r'[^_a-z0-9]+', '_', name.strip().lower()).strip('_')
    if tactic_name:
        pre = rulename_to_filename(name=tactic_name, ext='')
        name = f'{pre}_{name}'
    return name + ext or ''


def load_rule_contents(rule_file: Path, single_only=False) -> list:
    """Load a rule file from multiple formats."""
    _, extension = os.path.splitext(rule_file)
    raw_text = rule_file.read_text()

    if extension in ('.ndjson', '.jsonl'):
        # kibana exported rule object is ndjson with the export metadata on the last line
        contents = [json.loads(line) for line in raw_text.splitlines()]

        if len(contents) > 1 and 'exported_count' in contents[-1]:
            contents.pop(-1)

        if single_only and len(contents) > 1:
            raise ValueError('Multiple rules not allowed')

        return contents or [{}]
    elif extension == '.toml':
        rule = pytoml.loads(raw_text)
    elif extension.lower() in ('yaml', 'yml'):
        rule = load_dump(str(rule_file))
    else:
        return []

    if isinstance(rule, dict):
        return [rule]
    elif isinstance(rule, list):
        return rule
    else:
        raise ValueError(f"Expected a list or dictionary in {rule_file}")


def load_json_from_branch(repo: Repository, file_path: str, branch: Optional[str]):
    """Load JSON file from a specific branch."""
    content_file = repo.get_contents(file_path, ref=branch)
    return json.loads(content_file.decoded_content.decode("utf-8"))


def compare_versions(base_json: dict, branch_json: dict) -> list[tuple[str, str, int, int]]:
    """Compare versions of two lock version file JSON objects."""
    changes = []
    for key in base_json:
        if key in branch_json:
            base_version = base_json[key].get("version")
            branch_name = branch_json[key].get("rule_name")
            branch_version = branch_json[key].get("version")
            if base_version != branch_version:
                changes.append((key, branch_name, base_version, branch_version))
    return changes


def check_double_bumps(changes: list[tuple[str, str, int, int]]) -> list[tuple[str, str, int, int]]:
    """Check for double bumps in version changes of the result of compare versions of a version lock file."""
    double_bumps = []
    for key, name, removed, added in changes:
        # Determine the modulo dynamically based on the highest number of digits
        max_digits = max(len(str(removed)), len(str(added)))
        modulo = max(10 ** (max_digits - 1), 100)
        if (added % modulo) - (removed % modulo) > 1:
            double_bumps.append((key, name, removed, added))
    return double_bumps


def check_version_lock_double_bumps(
    repo: Repository, file_path: str, base_branch: str, branch: str = "", local_file: Path = None
) -> list[tuple[str, str, int, int]]:
    """Check for double bumps in version changes of the result of compare versions of a version lock file."""
    base_json = load_json_from_branch(repo, file_path, base_branch)
    if local_file:
        with local_file.open("r") as f:
            branch_json = json.load(f)
    else:
        branch_json = load_json_from_branch(repo, file_path, branch)

    changes = compare_versions(base_json, branch_json)
    double_bumps = check_double_bumps(changes)

    return double_bumps


def format_command_options(ctx):
    """Echo options for a click command."""
    formatter = ctx.make_formatter()
    opts = []

    for param in ctx.command.get_params(ctx):
        if param.name == 'help':
            continue

        rv = param.get_help_record(ctx)
        if rv is not None:
            opts.append(rv)

    if opts:
        with formatter.section('Options'):
            formatter.write_dl(opts)

    return formatter.getvalue()


def make_git(*prefix_args) -> Optional[Callable]:
    git_exe = shutil.which("git")
    prefix_args = [str(arg) for arg in prefix_args]

    if not git_exe:
        click.secho("Unable to find git", err=True, fg="red")
        ctx = click.get_current_context(silent=True)

        if ctx is not None:
            ctx.exit(1)

        return

    def git(*args, print_output=False):
        nonlocal prefix_args

        if '-C' not in prefix_args:
            prefix_args = ['-C', get_path()] + prefix_args

        full_args = [git_exe] + prefix_args + [str(arg) for arg in args]
        if print_output:
            return subprocess.check_call(full_args)
        return subprocess.check_output(full_args, encoding="utf-8").rstrip()

    return git


def git(*args, **kwargs):
    """Find and run a one-off Git command."""
    return make_git()(*args, **kwargs)


def add_params(*params):
    """Add parameters to a click command."""

    def decorator(f):
        if not hasattr(f, '__click_params__'):
            f.__click_params__ = []
        f.__click_params__.extend(params)
        return f

    return decorator


class Ndjson(list):
    """Wrapper for ndjson data."""

    def to_string(self, sort_keys: bool = False):
        """Format contents list to ndjson string."""
        return '\n'.join(json.dumps(c, sort_keys=sort_keys) for c in self) + '\n'

    @classmethod
    def from_string(cls, ndjson_string: str, **kwargs):
        """Load ndjson string to a list."""
        contents = [json.loads(line, **kwargs) for line in ndjson_string.strip().splitlines()]
        return Ndjson(contents)

    def dump(self, filename: Path, sort_keys=False):
        """Save contents to an ndjson file."""
        filename.write_text(self.to_string(sort_keys=sort_keys))

    @classmethod
    def load(cls, filename: Path, **kwargs):
        """Load content from an ndjson file."""
        return cls.from_string(filename.read_text(), **kwargs)


class PatchedTemplate(Template):
    """String template with updated methods from future versions."""

    def get_identifiers(self):
        """Returns a list of the valid identifiers in the template, in the order they first appear, ignoring any
        invalid identifiers."""
        # https://github.com/python/cpython/blob/3b4f8fc83dcea1a9d0bc5bd33592e5a3da41fa71/Lib/string.py#LL157-L171C19
        ids = []
        for mo in self.pattern.finditer(self.template):
            named = mo.group('named') or mo.group('braced')
            if named is not None and named not in ids:
                # add a named group only the first time it appears
                ids.append(named)
            elif named is None and mo.group('invalid') is None and mo.group('escaped') is None:
                # If all the groups are None, there must be
                # another group we're not expecting
                raise ValueError('Unrecognized named group in pattern',
                                 self.pattern)
        return ids

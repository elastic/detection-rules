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
import time
import zipfile
from dataclasses import is_dataclass, astuple
from datetime import datetime, date
from pathlib import Path

import eql.utils
from eql.utils import load_dump, stream_json_lines

import kql

CURR_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURR_DIR)
ETC_DIR = os.path.join(ROOT_DIR, "etc")


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


def dict_hash(obj: dict) -> str:
    """Hash a dictionary deterministically."""
    raw_bytes = base64.b64encode(json.dumps(obj, sort_keys=True).encode('utf-8'))
    return hashlib.sha256(raw_bytes).hexdigest()


def get_json_iter(f):
    """Get an iterator over a JSON file."""
    first = f.read(2)
    f.seek(0)

    if first[0] == '[' or first == "{\n":
        return json.load(f)
    else:
        data = list(stream_json_lines(f))
    return data


def get_path(*paths) -> str:
    """Get a file by relative path."""
    return os.path.join(ROOT_DIR, *paths)


def get_etc_path(*paths):
    """Load a file from the etc/ folder."""
    return os.path.join(ETC_DIR, *paths)


def get_etc_glob_path(*patterns):
    """Load a file from the etc/ folder."""
    pattern = os.path.join(*patterns)
    return glob.glob(os.path.join(ETC_DIR, pattern))


def get_etc_file(name, mode="r"):
    """Load a file from the etc/ folder."""
    with open(get_etc_path(name), mode) as f:
        return f.read()


def load_etc_dump(*path):
    """Load a json/yml/toml file from the etc/ folder."""
    return eql.utils.load_dump(get_etc_path(*path))


def save_etc_dump(contents, *path, **kwargs):
    """Load a json/yml/toml file from the etc/ folder."""
    path = get_etc_path(*path)
    _, ext = os.path.splitext(path)
    sort_keys = kwargs.pop('sort_keys', True)
    indent = kwargs.pop('indent', 2)

    if ext == ".json":
        with open(path, "wt") as f:
            json.dump(contents, f, cls=DateTimeEncoder, sort_keys=sort_keys, indent=indent, **kwargs)
    else:
        return eql.utils.save_dump(contents, path)


def gzip_compress(contents):
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


def event_sort(events, timestamp='@timestamp', date_format='%Y-%m-%dT%H:%M:%S.%f%z', asc=True):
    """Sort events from elasticsearch by timestamp."""

    def _event_sort(event):
        t = event[timestamp]
        return (time.mktime(time.strptime(t, date_format)) + int(t.split('.')[-1][:-1]) / 1000) * 1000

    return sorted(events, key=_event_sort, reverse=not asc)


def combine_sources(*sources):  # type: (list[list]) -> list
    """Combine lists of events from multiple sources."""
    combined = []
    for source in sources:
        combined.extend(source.copy())

    return event_sort(combined)


def evaluate(rule, events):
    """Evaluate a query against events."""
    evaluator = kql.get_evaluator(kql.parse(rule.query))
    filtered = list(filter(evaluator, events))
    return filtered


def unix_time_to_formatted(timestamp):  # type: (int|str) -> str
    """Converts unix time in seconds or milliseconds to the default format."""
    if isinstance(timestamp, (int, float)):
        if timestamp > 2 ** 32:
            timestamp = round(timestamp / 1000, 3)

        return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


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


def load_rule_contents(rule_file: str, single_only=False) -> list:
    """Load a rule file from multiple formats."""
    _, extension = os.path.splitext(rule_file)

    if extension in ('.ndjson', '.jsonl'):
        # kibana exported rule object is ndjson with the export metadata on the last line
        with open(rule_file, 'r') as f:
            contents = [json.loads(line) for line in f.readlines()]

            if len(contents) > 1 and 'exported_count' in contents[-1]:
                contents.pop(-1)

            if single_only and len(contents) > 1:
                raise ValueError('Multiple rules not allowed')

            return contents or [{}]
    else:
        rule = load_dump(rule_file)
        if isinstance(rule, dict):
            return [rule]
        elif isinstance(rule, list):
            return rule
        else:
            raise ValueError(f"Expected a list or dictionary in {rule_file}")


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

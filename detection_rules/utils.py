# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Util functions."""
import contextlib
import functools
import gzip
import io
import json
from pathlib import Path
import time
import zipfile
from datetime import datetime, date

import kql

import eql.utils
from eql.utils import load_dump, stream_json_lines

CURR_DIR = Path(__file__).parent
ROOT_DIR = CURR_DIR.parent
ETC_DIR = ROOT_DIR / 'etc'
RULES_DIR = ROOT_DIR / 'rules'
RTA_DIR = ROOT_DIR / 'rta'
RELEASE_DIR = ROOT_DIR / "releases"


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (date, datetime)):
            return obj.isoformat()


def get_json_iter(f):
    """Get an iterator over a JSON file."""
    first = f.read(2)
    f.seek(0)

    if first[0] == '[' or first == "{\n":
        return json.load(f)
    else:
        data = list(stream_json_lines(f))
    return data


def save_etc_dump(contents, *path, **kwargs):
    """Save a json/yml/toml file to the etc/ folder."""
    path = ETC_DIR / Path(*path)
    _, ext = path.parent, path.suffix
    sort_keys = kwargs.pop('sort_keys', True)
    indent = kwargs.pop('indent', 2)

    if ext == ".json":
        with open(path, "wt") as f:
            json.dump(contents, f, cls=DateTimeEncoder, sort_keys=sort_keys, indent=indent, **kwargs)
    else:
        # TODO Remove str when eql.utils.save_dump takes a Path object as input
        return eql.utils.save_dump(contents, str(path))


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
    if isinstance(obj, (list, tuple)):
        return tuple(freeze(o) for o in obj)
    elif isinstance(obj, dict):
        return freeze(list(sorted(obj.items())))
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


def load_rule_contents(rule_file: Path, single_only=False) -> list:
    """Load a rule file from multiple formats."""
    _, extension = rule_file.parent, rule_file.suffix

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
        rule = load_dump(str(rule_file))
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

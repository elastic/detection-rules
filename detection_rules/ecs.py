# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""ECS Schemas management."""
import copy
import glob
import os
import shutil
import json

import requests
import eql
import eql.types
import yaml

from .semver import Version
from .utils import DateTimeEncoder, cached, load_etc_dump, get_etc_path, gzip_compress, read_gzip, unzip

ETC_NAME = "ecs_schemas"
ECS_SCHEMAS_DIR = get_etc_path(ETC_NAME)


def add_field(schema, name, info):
    """Nest a dotted field within a dictionary."""
    if "." not in name:
        schema[name] = info
        return

    top, remaining = name.split(".", 1)
    if not isinstance(schema.get(top), dict):
        schema[top] = {}
    add_field(schema, remaining, info)


def nest_from_dot(dots, value):
    """Nest a dotted field and set the inner most value."""
    fields = dots.split('.')

    if not fields:
        return {}

    nested = {fields.pop(): value}

    for field in reversed(fields):
        nested = {field: nested}

    return nested


def _recursive_merge(existing, new, depth=0):
    """Return an existing dict merged into a new one."""
    for key, value in existing.items():
        if isinstance(value, dict):
            if depth == 0:
                new = copy.deepcopy(new)

            node = new.setdefault(key, {})
            _recursive_merge(value, node, depth + 1)
        else:
            new[key] = value

    return new


def get_schema_files():
    """Get schema files from ecs directory."""
    return glob.glob(os.path.join(ECS_SCHEMAS_DIR, '*', '*.json.gz'), recursive=True)


def get_schema_map():
    """Get local schema files by version."""
    schema_map = {}

    for file_name in get_schema_files():
        path, name = os.path.split(file_name)
        name = name.split('.')[0]
        version = os.path.basename(path)
        schema_map.setdefault(version, {})[name] = file_name

    return schema_map


@cached
def get_schemas():
    """Get local schemas."""
    schema_map = get_schema_map()

    for version, values in schema_map.items():
        for name, file_name in values.items():
            schema_map[version][name] = json.loads(read_gzip(file_name))

    return schema_map


def get_max_version(include_master=False):
    """Get maximum available schema version."""
    versions = get_schema_map().keys()

    if include_master and any([v.startswith('master') for v in versions]):
        return glob.glob(os.path.join(ECS_SCHEMAS_DIR, 'master*'))[0]

    return str(max([Version(v) for v in versions if not v.startswith('master')]))


@cached
def get_schema(version=None, name='ecs_flat'):
    """Get schema by version."""
    return get_schemas()[version][name]


@cached
def get_eql_schema(version=None, index_patterns=None):
    """Return schema in expected format for eql."""
    schema = get_schema(version, name='ecs_flat')
    str_types = ('text', 'ip', 'keyword', 'date', 'object', 'geo_point')
    num_types = ('float', 'integer', 'long')
    schema = schema.copy()

    def convert_type(t):
        return 'string' if t in str_types else 'number' if t in num_types else 'boolean'

    converted = {}

    for field, schema_info in schema.items():
        field_type = schema_info.get('type', '')
        add_field(converted, field, convert_type(field_type))

    if index_patterns:
        for index_name in index_patterns:
            for k, v in flatten(get_index_schema(index_name)).items():
                add_field(converted, k, convert_type(v))

    return converted


def flatten(schema):
    flattened = {}
    for k, v in schema.items():
        if isinstance(v, dict):
            flattened.update((k + "." + vk, vv) for vk, vv in flatten(v).items())
        else:
            flattened[k] = v
    return flattened


@cached
def get_non_ecs_schema():
    """Load non-ecs schema."""
    return load_etc_dump('non-ecs-schema.json')


@cached
def get_index_schema(index_name):
    return get_non_ecs_schema().get(index_name, {})


def flatten_multi_fields(schema):
    converted = {}
    for field, info in schema.items():
        converted[field] = info["type"]
        for subfield in info.get("multi_fields", []):
            converted[field + "." + subfield["name"]] = subfield["type"]

    return converted


class KqlSchema2Eql(eql.Schema):
    type_mapping = {
        "keyword": eql.types.TypeHint.String,
        "ip": eql.types.TypeHint.String,
        "float": eql.types.TypeHint.Numeric,
        "double": eql.types.TypeHint.Numeric,
        "long": eql.types.TypeHint.Numeric,
        "short": eql.types.TypeHint.Numeric,
        "boolean": eql.types.TypeHint.Boolean,
    }

    def __init__(self, kql_schema):
        self.kql_schema = kql_schema
        eql.Schema.__init__(self, {}, allow_any=True, allow_generic=False, allow_missing=False)

    def validate_event_type(self, event_type):
        # allow all event types to fill in X:
        #   `X` where ....
        return True

    def get_event_type_hint(self, event_type, path):
        dotted = ".".join(path)
        elasticsearch_type = self.kql_schema.get(dotted)
        eql_hint = self.type_mapping.get(elasticsearch_type)

        if eql_hint is not None:
            return eql_hint, None


@cached
def get_kql_schema(version=None, indexes=None, beat_schema=None):
    """Get schema for KQL."""
    indexes = indexes or ()
    converted = flatten_multi_fields(get_schema(version, name='ecs_flat'))

    for index_name in indexes:
        converted.update(**flatten(get_index_schema(index_name)))

    if isinstance(beat_schema, dict):
        converted = dict(flatten_multi_fields(beat_schema), **converted)

    return converted


def download_schemas(refresh_master=True, refresh_all=False, verbose=True):
    """Download additional schemas from ecs releases."""
    existing = [Version(v) for v in get_schema_map()] if not refresh_all else []
    url = 'https://api.github.com/repos/elastic/ecs/releases'
    releases = requests.get(url)

    for release in releases.json():
        version = Version(release.get('tag_name', '').lstrip('v'))

        # we don't ever want beta
        if not version or version < (1, 0, 1) or version in existing:
            continue

        schema_dir = os.path.join(ECS_SCHEMAS_DIR, str(version))

        with unzip(requests.get(release['zipball_url']).content) as archive:
            name_list = archive.namelist()
            base = name_list[0]

            # members = [m for m in name_list if m.startswith('{}{}/'.format(base, 'use-cases')) and m.endswith('.yml')]
            members = ['{}generated/ecs/ecs_flat.yml'.format(base), '{}generated/ecs/ecs_nested.yml'.format(base)]
            saved = []

            for member in members:
                file_name = os.path.basename(member)
                os.makedirs(schema_dir, exist_ok=True)

                # load as yaml, save as json
                contents = yaml.safe_load(archive.read(member))
                out_file = file_name.replace(".yml", ".json.gz")

                compressed = gzip_compress(json.dumps(contents, sort_keys=True, cls=DateTimeEncoder))
                new_path = get_etc_path(ETC_NAME, str(version), out_file)
                with open(new_path, 'wb') as f:
                    f.write(compressed)

                saved.append(out_file)

            if verbose:
                print('Saved files to {}: \n\t- {}'.format(schema_dir, '\n\t- '.join(saved)))

    # handle working master separately
    if refresh_master:
        master_ver = requests.get('https://raw.githubusercontent.com/elastic/ecs/master/version')
        master_ver = Version(master_ver.text.strip())
        master_schema = requests.get('https://raw.githubusercontent.com/elastic/ecs/master/generated/ecs/ecs_flat.yml')
        master_schema = yaml.safe_load(master_schema.text)

        # prepend with underscore so that we can differentiate the fact that this is a working master version
        #   but first clear out any existing masters, since we only ever want 1 at a time
        existing_master = glob.glob(os.path.join(ECS_SCHEMAS_DIR, 'master_*'))
        for m in existing_master:
            shutil.rmtree(m, ignore_errors=True)

        master_dir = "master_{}".format(master_ver)
        os.makedirs(get_etc_path(ETC_NAME, master_dir), exist_ok=True)

        compressed = gzip_compress(json.dumps(master_schema, sort_keys=True, cls=DateTimeEncoder))
        new_path = get_etc_path(ETC_NAME, master_dir, "ecs_flat.json.gz")
        with open(new_path, 'wb') as f:
            f.write(compressed)

        if verbose:
            print('Saved files to {}: \n\t- {}'.format(master_dir, 'ecs_flat.json.gz'))

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""ECS Schemas management."""
import os
import re

import kql
import eql
import json
import requests
import yaml

from .semver import Version
from .utils import DateTimeEncoder, unzip, get_etc_path, gzip_compress, read_gzip, cached


def download_latest_beats_schema():
    """Download additional schemas from ecs releases."""
    url = 'https://api.github.com/repos/elastic/beats/releases'
    releases = requests.get(url)

    latest_release = max(releases.json(), key=lambda release: Version(release["tag_name"].lstrip("v")))

    print(f"Downloading beats {latest_release['tag_name']}")
    response = requests.get(latest_release['zipball_url'])

    print(f"Downloaded {len(response.content) / 1024.0 / 1024.0:.2f} MB release.")

    fs = {}
    parsed = {}

    with unzip(response.content) as archive:
        base_directory = archive.namelist()[0]

        for name in archive.namelist():
            if os.path.basename(name) in ("fields.yml", "fields.common.yml", "config.yml"):
                contents = archive.read(name)

                # chop off the base directory name
                key = name[len(base_directory):]

                if key.startswith("x-pack"):
                    key = key[len("x-pack") + 1:]

                try:
                    decoded = yaml.safe_load(contents)
                except yaml.YAMLError:
                    print(f"Error loading {name}")

                # create a hierarchical structure
                parsed[key] = decoded
                branch = fs
                directory, base_name = os.path.split(key)
                for limb in directory.split(os.path.sep):
                    branch = branch.setdefault("folders", {}).setdefault(limb, {})

                branch.setdefault("files", {})[base_name] = decoded

    # remove all non-beat directories
    fs = {k: v for k, v in fs.get("folders", {}).items() if k.endswith("beat")}
    print(f"Saving etc/beats_schema/{latest_release['tag_name']}.json")

    compressed = gzip_compress(json.dumps(fs, sort_keys=True, cls=DateTimeEncoder))
    path = get_etc_path("beats_schemas", latest_release["tag_name"] + ".json.gz")
    with open(path, 'wb') as f:
        f.write(compressed)


def _flatten_schema(schema: list, prefix="") -> list:
    if schema is None:
        # sometimes we see `fields: null` in the yaml
        return []

    flattened = []
    for s in schema:
        if s.get("type") == "group":
            nested_prefix = prefix + s["name"] + "."
            # beats is complicated. it seems lke we would expect a zoom.webhook.*, for the zoom.webhook dataset,
            # but instead it's just at zoom.* directly.
            #
            # we have what looks like zoom.zoom.*, but should actually just be zoom.*.
            # this is one quick heuristic to determine if a submodule nests fields at the parent.
            # it's probably not perfect, but we can fix other bugs as we run into them later
            if len(schema) == 1 and nested_prefix == prefix + prefix:
                nested_prefix = prefix
            flattened.extend(_flatten_schema(s["fields"], prefix=nested_prefix))
        elif "fields" in s:
            flattened.extend(_flatten_schema(s["fields"], prefix=prefix))
        elif "name" in s and "description" in s:
            s = s.copy()
            # type is implicitly keyword if not defined
            # example: https://github.com/elastic/beats/blob/master/packetbeat/_meta/fields.common.yml#L7-L12
            s.setdefault("type", "keyword")
            s["name"] = prefix + s["name"]
            flattened.append(s)

    return flattened


def get_field_schema(base_directory, prefix="", include_common=False):
    base_directory = base_directory.get("folders", {}).get("_meta", {}).get("files", {})
    flattened = []

    file_names = ("fields.yml", "fields.common.yml") if include_common else ("fields.yml", )

    for name in file_names:
        if name in base_directory:
            flattened.extend(_flatten_schema(base_directory[name], prefix=prefix))

    return flattened


def get_beat_root_schema(schema: dict, beat: str):
    if beat not in schema:
        raise KeyError(f"Unknown beats module {beat}")

    beat_dir = schema[beat]
    flattened = get_field_schema(beat_dir, include_common=True)

    return {field["name"]: field for field in sorted(flattened, key=lambda f: f["name"])}


def get_beats_sub_schema(schema: dict, beat: str, module: str, *datasets: str):
    if beat not in schema:
        raise KeyError(f"Unknown beats module {beat}")

    flattened = []
    beat_dir = schema[beat]
    module_dir = beat_dir.get("folders", {}).get("module", {}).get("folders", {}).get(module, {})

    # if we only have a module then we'll work with what we got
    if not datasets:
        datasets = [d for d in module_dir.get("folders", {}) if not d.startswith("_")]

    for dataset in datasets:
        # replace aws.s3 -> s3
        if dataset.startswith(module + "."):
            dataset = dataset[len(module) + 1:]

        dataset_dir = module_dir.get("folders", {}).get(dataset, {})
        flattened.extend(get_field_schema(dataset_dir, prefix=module + ".", include_common=True))

    return {field["name"]: field for field in sorted(flattened, key=lambda f: f["name"])}


@cached
def get_versions():
    versions = []
    for filename in os.listdir(get_etc_path("beats_schemas")):
        version_match = re.match(r'v(.+)\.json\.gz', filename)
        if version_match:
            versions.append(Version(version_match.groups()[0]))

    return versions


@cached
def get_max_version():
    return max(get_versions())


@cached
def read_beats_schema(version: str = None):
    version = Version(version) if version else None
    beats_schemas = get_versions()

    if version and version not in beats_schemas:
        raise ValueError(f'Unknown beats schema: {version}')

    version = version or max(beats_schemas)

    return json.loads(read_gzip(get_etc_path('beats_schemas', f'v{version}.json.gz')))


def get_schema_from_datasets(beats, modules, datasets, version=None):
    filtered = {}
    beats_schema = read_beats_schema(version=version)

    # infer the module if only a dataset are defined
    if not modules:
        modules.update(ds.split(".")[0] for ds in datasets if "." in ds)

    for beat in beats:
        # if no modules are specified then grab them all
        # all_modules = list(beats_schema.get(beat, {}).get("folders", {}).get("module", {}).get("folders", {}))
        # beat_modules = modules or all_modules
        filtered.update(get_beat_root_schema(beats_schema, beat))

        for module in modules:
            filtered.update(get_beats_sub_schema(beats_schema, beat, module, *datasets))

    return filtered


def get_schema_from_eql(tree: eql.ast.BaseNode, beats: list, version: str = None) -> dict:
    modules = set()
    datasets = set()

    # extract out event.module and event.dataset from the query's AST
    for node in tree:
        if isinstance(node, eql.ast.Comparison) and node.comparator == node.EQ and \
                isinstance(node.right, eql.ast.String):
            if node.left == eql.ast.Field("event", ["module"]):
                modules.add(node.right.render())
            elif node.left == eql.ast.Field("event", ["dataset"]):
                datasets.add(node.right.render())
        elif isinstance(node, eql.ast.InSet):
            if node.expression == eql.ast.Field("event", ["module"]):
                modules.add(node.get_literals())
            elif node.expression == eql.ast.Field("event", ["dataset"]):
                datasets.add(node.get_literals())

    return get_schema_from_datasets(beats, modules, datasets, version=version)


def get_schema_from_kql(tree: kql.ast.BaseNode, beats: list, version: str = None) -> dict:
    modules = set()
    datasets = set()

    # extract out event.module and event.dataset from the query's AST
    for node in tree:
        if isinstance(node, kql.ast.FieldComparison) and node.field == kql.ast.Field("event.module"):
            modules.update(child.value for child in node.value if isinstance(child, kql.ast.String))

        if isinstance(node, kql.ast.FieldComparison) and node.field == kql.ast.Field("event.dataset"):
            datasets.update(child.value for child in node.value if isinstance(child, kql.ast.String))

    return get_schema_from_datasets(beats, modules, datasets, version=version)

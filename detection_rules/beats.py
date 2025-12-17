# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""ECS Schemas management."""

import json
import os
import re
from pathlib import Path
from typing import Any

import eql  # type: ignore[reportMissingTypeStubs]
import kql  # type: ignore[reportMissingTypeStubs]
import requests
import yaml
from semver import Version

from .utils import DateTimeEncoder, cached, get_etc_path, gzip_compress, read_gzip, unzip


def _decompress_and_save_schema(url: str, release_name: str) -> None:
    print(f"Downloading beats {release_name}", url)
    response = requests.get(url, timeout=30)

    print(f"Downloaded {len(response.content) / 1024.0 / 1024.0:.2f} MB release.")

    fs: dict[str, Any] = {}

    with unzip(response.content) as archive:
        base_directory = archive.namelist()[0]

        for name in archive.namelist():
            path = Path(name)
            if path.name in ("fields.yml", "fields.common.yml", "config.yml"):
                # chop off the base directory name
                key = name[len(base_directory) :]

                if key.startswith("x-pack"):
                    key = key[len("x-pack") + 1 :]

                # create a hierarchical structure
                branch = fs
                directory, base_name = os.path.split(key)
                for limb in directory.split(os.path.sep):
                    branch = branch.setdefault("folders", {}).setdefault(limb, {})

                contents = archive.read(name)
                try:
                    decoded = yaml.safe_load(contents)
                except yaml.YAMLError:
                    print(f"Error loading {name}, not a valid YAML")
                    decoded = None

                branch.setdefault("files", {})[base_name] = decoded

    # remove all non-beat directories
    fs = {k: v for k, v in fs.get("folders", {}).items() if k.endswith("beat")}
    print(f"Saving detection_rules/etc/beats_schema/{release_name}.json")

    compressed = gzip_compress(json.dumps(fs, sort_keys=True, cls=DateTimeEncoder))
    path = get_etc_path(["beats_schemas", release_name + ".json.gz"])
    with path.open("wb") as f:
        _ = f.write(compressed)


def download_beats_schema(version: str) -> None:
    """Download a beats schema by version."""
    url = "https://api.github.com/repos/elastic/beats/releases"
    releases = requests.get(url, timeout=30)

    version = f"v{version.lstrip('v')}"
    beats_release = None
    for release in releases.json():
        if release["tag_name"] == version:
            beats_release = release
            break

    if not beats_release:
        print(f"beats release {version} not found!")
        return

    beats_url = beats_release["zipball_url"]
    name = beats_release["tag_name"]

    _decompress_and_save_schema(beats_url, name)


def download_latest_beats_schema() -> None:
    """Download additional schemas from beats releases."""
    url = "https://api.github.com/repos/elastic/beats/releases"
    releases = requests.get(url, timeout=30)

    latest_release = max(releases.json(), key=lambda release: Version.parse(release["tag_name"].lstrip("v")))
    download_beats_schema(latest_release["tag_name"])


def refresh_main_schema() -> None:
    """Download and refresh beats schema from main."""
    _decompress_and_save_schema("https://github.com/elastic/beats/archive/main.zip", "main")


def _flatten_schema(schema: list[dict[str, Any]] | None, prefix: str = "") -> list[dict[str, Any]]:
    if schema is None:
        # sometimes we see `fields: null` in the yaml
        return []

    flattened: list[dict[str, Any]] = []
    for s in schema:
        if s.get("type") == "group":
            nested_prefix = prefix + s["name"] + "."
            # beats is complicated. it seems like we would expect a zoom.webhook.*, for the zoom.webhook dataset,
            # but instead it's just at zoom.* directly.
            #
            # we have what looks like zoom.zoom.*, but should actually just be zoom.*.
            # this is one quick heuristic to determine if a submodule nests fields at the parent.
            # it's probably not perfect, but we can fix other bugs as we run into them later
            if len(schema) == 1 and nested_prefix.startswith(prefix + prefix):
                nested_prefix = s["name"] + "."
            if "field" in s:
                # integrations sometimes have a group with a single field
                flattened.extend(_flatten_schema(s["field"], prefix=nested_prefix))
                continue
            if "fields" not in s:
                # integrations sometimes have a group with no fields
                continue

            flattened.extend(_flatten_schema(s["fields"], prefix=nested_prefix))
        elif "fields" in s:
            if s.get("name") and s.get("type") == "nested":
                nested_prefix = prefix + s["name"] + "."
                flattened.extend(_flatten_schema(s["fields"], prefix=nested_prefix))
            else:
                flattened.extend(_flatten_schema(s["fields"], prefix=prefix))
        elif "name" in s:
            _s = s.copy()
            # type is implicitly keyword if not defined
            # example: https://github.com/elastic/beats/blob/main/packetbeat/_meta/fields.common.yml#L7-L12
            _s.setdefault("type", "keyword")
            _s["name"] = prefix + s["name"]
            flattened.append(_s)

    return flattened


def flatten_ecs_schema(schema: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return _flatten_schema(schema)


def get_field_schema(
    base_directory: dict[str, Any],
    prefix: str = "",
    include_common: bool = False,
) -> list[dict[str, Any]]:
    base_directory = base_directory.get("folders", {}).get("_meta", {}).get("files", {})
    flattened: list[dict[str, Any]] = []

    file_names = ("fields.yml", "fields.common.yml") if include_common else ("fields.yml",)

    for name in file_names:
        if name in base_directory:
            flattened.extend(_flatten_schema(base_directory[name], prefix=prefix))

    return flattened


def get_beat_root_schema(schema: dict[str, Any], beat: str) -> dict[str, Any]:
    if beat not in schema:
        raise KeyError(f"Unknown beats module {beat}")

    beat_dir = schema[beat]
    flattened = get_field_schema(beat_dir, include_common=True)

    return {field["name"]: field for field in sorted(flattened, key=lambda f: f["name"])}


def get_beats_sub_schema(schema: dict[str, Any], beat: str, module: str, *datasets: str) -> dict[str, Any]:
    if beat not in schema:
        raise KeyError(f"Unknown beats module {beat}")

    flattened: list[dict[str, Any]] = []
    beat_dir = schema[beat]
    # Normalize module name in case callers include quotes from rendered AST
    normalized_module = module.strip("\"' ")
    module_dir = beat_dir.get("folders", {}).get("module", {}).get("folders", {}).get(normalized_module, {})

    # if we only have a module then we'll work with what we got
    all_datasets = datasets if datasets else [d for d in module_dir.get("folders", {}) if not d.startswith("_")]

    for _dataset in all_datasets:
        # replace aws.s3 -> s3
        ds = _dataset.strip("\"' ")
        dataset = ds[len(normalized_module) + 1 :] if ds.startswith(normalized_module + ".") else ds

        dataset_dir = module_dir.get("folders", {}).get(dataset, {})
        flattened.extend(get_field_schema(dataset_dir, prefix=normalized_module + ".", include_common=True))

    # we also need to capture (beta?) fields which are directly within the module _meta.files.fields
    flattened.extend(get_field_schema(module_dir, include_common=True))

    return {field["name"]: field for field in sorted(flattened, key=lambda f: f["name"])}


@cached
def get_versions() -> list[Version]:
    versions: list[Version] = []
    for filename in os.listdir(get_etc_path(["beats_schemas"])):  # noqa: PTH208
        version_match = re.match(r"v(.+)\.json\.gz", filename)
        if version_match:
            versions.append(Version.parse(version_match.groups()[0]))

    return versions


@cached
def get_max_version() -> str:
    return str(max(get_versions()))


@cached
def read_beats_schema(version: str | None = None) -> dict[str, Any]:
    if version and version.lower() == "main":
        path = get_etc_path(["beats_schemas", "main.json.gz"])
        return json.loads(read_gzip(path))

    ver = Version.parse(version) if version else None
    beats_schemas = get_versions()

    if ver and ver not in beats_schemas:
        raise ValueError(f"Unknown beats schema: {ver}")

    version = version or get_max_version()

    return json.loads(read_gzip(get_etc_path(["beats_schemas", f"v{version}.json.gz"])))


def get_schema_from_datasets(
    beats: list[str],
    modules: set[str],
    datasets: set[str],
    version: str | None = None,
) -> dict[str, Any]:
    filtered: dict[str, Any] = {}
    beats_schema = read_beats_schema(version=version)

    # infer the module if only a dataset are defined
    if not modules:
        modules.update(ds.split(".")[0] for ds in datasets if "." in ds)

    for beat in beats:
        # if no modules are specified then grab them all
        filtered.update(get_beat_root_schema(beats_schema, beat))

        for module in modules:
            filtered.update(get_beats_sub_schema(beats_schema, beat, module, *datasets))

    return filtered


def get_datasets_and_modules(tree: eql.ast.BaseNode | kql.ast.BaseNode) -> tuple[set[str], set[str]]:
    """Get datasets and modules from an EQL or KQL AST."""
    modules: set[str] = set()
    datasets: set[str] = set()

    # extract out event.module, data_stream.dataset, and event.dataset from the query's AST
    for node in tree:  # type: ignore[reportUnknownVariableType]
        if (
            isinstance(node, eql.ast.Comparison)
            and node.comparator == node.EQ
            and isinstance(node.right, eql.ast.String)
        ):
            if node.left == eql.ast.Field("event", ["module"]):
                modules.add(node.right.value)  # type: ignore[reportUnknownMemberType]
            elif node.left == eql.ast.Field("event", ["dataset"]) or node.left == eql.ast.Field(
                "data_stream", ["dataset"]
            ):
                datasets.add(node.right.value)  # type: ignore[reportUnknownMemberType]
        elif isinstance(node, eql.ast.InSet):
            if node.expression == eql.ast.Field("event", ["module"]):
                modules.update(node.get_literals())  # type: ignore[reportUnknownMemberType]
            elif node.expression == eql.ast.Field("event", ["dataset"]) or node.expression == eql.ast.Field(
                "data_stream", ["dataset"]
            ):
                datasets.update(node.get_literals())  # type: ignore[reportUnknownMemberType]
        elif isinstance(node, kql.ast.FieldComparison) and node.field == kql.ast.Field("event.module"):  # type: ignore[reportUnknownMemberType]
            modules.update(child.value for child in node.value if isinstance(child, kql.ast.String))  # type: ignore[reportUnknownMemberType, reportUnknownVariableType]
        elif isinstance(node, kql.ast.FieldComparison) and node.field == kql.ast.Field("event.dataset"):  # type: ignore[reportUnknownMemberType]
            datasets.update(child.value for child in node.value if isinstance(child, kql.ast.String))  # type: ignore[reportUnknownMemberType, reportUnknownVariableType]
        elif isinstance(node, kql.ast.FieldComparison) and node.field == kql.ast.Field("data_stream.dataset"):  # type: ignore[reportUnknownMemberType]
            datasets.update(child.value for child in node.value if isinstance(child, kql.ast.String))  # type: ignore[reportUnknownMemberType]

    return datasets, modules


def get_schema_from_kql(tree: kql.ast.BaseNode, beats: list[str], version: str | None = None) -> dict[str, Any]:
    """Get a schema based on datasets and modules in an KQL AST."""
    datasets, modules = get_datasets_and_modules(tree)
    return get_schema_from_datasets(beats, modules, datasets, version=version)


def parse_beats_from_index(indexes: list[str] | None) -> list[str]:
    """Parse beats schema types from index."""
    indexes = indexes or []
    beat_types: list[str] = []
    # Need to split on : or :: to support cross-cluster search
    # e.g. mycluster:logs-* -> logs-*
    for index in indexes:
        if "beat-*" in index:
            index_parts = index.replace("::", ":").split(":", 1)
            last_part = index_parts[-1]
            beat_type = last_part.split("-")[0]
            beat_types.append(beat_type)
    return beat_types

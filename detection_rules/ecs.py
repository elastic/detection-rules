# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""ECS Schemas management."""

import copy
import json
import os
import shutil
from pathlib import Path
from typing import Any

import eql  # type: ignore[reportMissingTypeStubs]
import eql.types  # type: ignore[reportMissingTypeStubs]
import requests
import yaml
from semver import Version

from .config import CUSTOM_RULES_DIR, parse_rules_config
from .custom_schemas import get_custom_schemas
from .integrations import load_integrations_schemas
from .utils import DateTimeEncoder, cached, get_etc_path, gzip_compress, load_etc_dump, read_gzip, unzip

ECS_NAME = "ecs_schemas"
ECS_SCHEMAS_DIR = get_etc_path([ECS_NAME])
ENDPOINT_NAME = "endpoint_schemas"
ENDPOINT_SCHEMAS_DIR = get_etc_path([ENDPOINT_NAME])
RULES_CONFIG = parse_rules_config()


def add_field(schema: dict[str, Any], name: str, info: Any) -> None:
    """Nest a dotted field within a dictionary."""
    if "." not in name:
        schema[name] = info
        return

    top, remaining = name.split(".", 1)
    if not isinstance(schema.get(top), dict):
        schema[top] = {}
    add_field(schema, remaining, info)


def _recursive_merge(existing: dict[str, Any], new: dict[str, Any], depth: int = 0) -> dict[str, Any]:
    """Return an existing dict merged into a new one."""
    for key, value in existing.items():
        if isinstance(value, dict):
            if depth == 0:
                new = copy.deepcopy(new)

            node = new.setdefault(key, {})
            _ = _recursive_merge(value, node, depth + 1)  # type: ignore[reportUnknownArgumentType]
        else:
            new[key] = value

    return new


def get_schema_files() -> list[Path]:
    """Get schema files from ecs directory."""
    return list(ECS_SCHEMAS_DIR.glob("**/*.json.gz"))


def get_schema_map() -> dict[str, Any]:
    """Get local schema files by version."""
    schema_map: dict[str, Any] = {}

    for file_name in get_schema_files():
        path, name = os.path.split(file_name)
        name = name.split(".")[0]
        version = Path(path).name
        schema_map.setdefault(version, {})[name] = file_name

    return schema_map


@cached
def get_schemas() -> dict[str, Any]:
    """Get local schemas."""
    schema_map = get_schema_map()

    for version, values in schema_map.items():
        for name, file_name in values.items():
            schema_map[version][name] = json.loads(read_gzip(file_name))

    return schema_map


def get_max_version(include_master: bool = False) -> str:
    """Get maximum available schema version."""
    versions = get_schema_map().keys()

    if include_master and any(v.startswith("master") for v in versions):
        paths = list(ECS_SCHEMAS_DIR.glob("master*"))
        return paths[0].name

    return str(max([Version.parse(v) for v in versions if not v.startswith("master")]))


@cached
def get_schema(version: str | None = None, name: str = "ecs_flat") -> dict[str, Any]:
    """Get schema by version."""
    if version == "master":
        version = get_max_version(include_master=True)

    return get_schemas()[version or str(get_max_version())][name]


@cached
def get_eql_schema(version: str | None = None, index_patterns: list[str] | None = None) -> dict[str, Any]:
    """Return schema in expected format for eql."""
    schema = get_schema(version, name="ecs_flat")
    str_types = ("text", "ip", "keyword", "date", "object", "geo_point")
    num_types = ("float", "integer", "long")
    schema = schema.copy()

    def convert_type(t: str) -> str:
        return "string" if t in str_types else "number" if t in num_types else "boolean"

    converted: dict[str, Any] = {}

    for field, schema_info in schema.items():
        field_type = schema_info.get("type", "")
        add_field(converted, field, convert_type(field_type))

    # add non-ecs schema
    if index_patterns:
        for index_name in index_patterns:
            for k, v in flatten(get_index_schema(index_name)).items():
                add_field(converted, k, convert_type(v))

    # add custom schema
    if index_patterns and CUSTOM_RULES_DIR:
        for index_name in index_patterns:
            for k, v in flatten(get_custom_index_schema(index_name)).items():
                add_field(converted, k, convert_type(v))

    # add endpoint custom schema
    for k, v in flatten(get_endpoint_schemas()).items():
        add_field(converted, k, convert_type(v))

    return converted


def flatten(schema: dict[str, Any]) -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    for k, v in schema.items():
        if isinstance(v, dict):
            flattened.update((k + "." + vk, vv) for vk, vv in flatten(v).items())  # type: ignore[reportUnknownArgumentType]
        else:
            flattened[k] = v
    return flattened


@cached
def get_all_flattened_schema() -> dict[str, Any]:
    """Load all schemas into a flattened dictionary."""
    all_flattened_schema: dict[str, Any] = {}
    for schema in get_non_ecs_schema().values():
        all_flattened_schema.update(flatten(schema))

    ecs_schemas = get_schemas()
    for version in ecs_schemas:
        for index, info in ecs_schemas[version]["ecs_flat"].items():
            all_flattened_schema.update({index: info["type"]})

    for integration_schema in load_integrations_schemas().values():
        for index_schema in integration_schema.values():
            # Detect if ML integration
            if "jobs" in index_schema:
                ml_schemas = {k: v for k, v in index_schema.items() if k != "jobs"}
                for ml_schema in ml_schemas.values():
                    all_flattened_schema.update(flatten(ml_schema))
            else:
                all_flattened_schema.update(flatten(index_schema))

    return all_flattened_schema


@cached
def get_non_ecs_schema() -> Any:
    """Load non-ecs schema."""
    return load_etc_dump(["non-ecs-schema.json"])


@cached
def get_custom_index_schema(index_name: str, stack_version: str | None = None) -> Any:
    """Load custom schema."""
    custom_schemas = get_custom_schemas(stack_version)
    index_schema = custom_schemas.get(index_name, {})
    ccs_schema = custom_schemas.get(index_name.replace("::", ":").split(":", 1)[-1], {})
    index_schema.update(ccs_schema)
    return index_schema


@cached
def get_index_schema(index_name: str) -> Any:
    """Load non-ecs schema."""
    non_ecs_schema = get_non_ecs_schema()
    index_schema = non_ecs_schema.get(index_name, {})
    ccs_schema = non_ecs_schema.get(index_name.replace("::", ":").split(":", 1)[-1], {})
    index_schema.update(ccs_schema)
    return index_schema


def flatten_multi_fields(schema: dict[str, Any]) -> dict[str, Any]:
    converted: dict[str, Any] = {}
    for field, info in schema.items():
        converted[field] = info["type"]
        for subfield in info.get("multi_fields", []):
            converted[field + "." + subfield["name"]] = subfield["type"]

    return converted


class KqlSchema2Eql(eql.Schema):
    type_mapping = {  # noqa: RUF012
        "keyword": eql.types.TypeHint.String,
        "ip": eql.types.TypeHint.String,
        "float": eql.types.TypeHint.Numeric,
        "integer": eql.types.TypeHint.Numeric,
        "boolean": eql.types.TypeHint.Boolean,
    }

    def __init__(self, kql_schema: dict[str, Any]) -> None:
        self.kql_schema = kql_schema
        eql.Schema.__init__(self, {}, allow_any=True, allow_generic=False, allow_missing=False)  # type: ignore[reportUnknownMemberType]

    def validate_event_type(self, _: Any) -> bool:  # type: ignore[reportIncompatibleMethodOverride]
        # allow all event types to fill in X:
        #   `X` where ....
        return True

    def get_event_type_hint(self, _: Any, path: list[str]) -> tuple[Any, None]:  # type: ignore[reportIncompatibleMethodOverride]
        from kql.parser import elasticsearch_type_family  # type: ignore[reportMissingTypeStubs]

        dotted = ".".join(path)
        elasticsearch_type = self.kql_schema.get(dotted)
        if not elasticsearch_type:
            return None, None

        es_type_family = elasticsearch_type_family(elasticsearch_type)
        eql_hint = self.type_mapping.get(es_type_family)

        if eql_hint is not None:
            return eql_hint, None

        return None, None


@cached
def get_kql_schema(
    version: str | None = None,
    indexes: list[str] | None = None,
    beat_schema: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Get schema for KQL."""
    indexes = indexes or []
    converted = flatten_multi_fields(get_schema(version, name="ecs_flat"))

    # non-ecs schema
    for index_name in indexes:
        converted.update(**flatten(get_index_schema(index_name)))

    # custom schema
    if CUSTOM_RULES_DIR:
        for index_name in indexes:
            converted.update(**flatten(get_custom_index_schema(index_name)))

    # add endpoint custom schema
    converted.update(**flatten(get_endpoint_schemas()))

    if isinstance(beat_schema, dict):
        converted = dict(flatten_multi_fields(beat_schema), **converted)

    return converted


def download_schemas(refresh_master: bool = True, refresh_all: bool = False, verbose: bool = True) -> None:
    """Download additional schemas from ecs releases."""
    existing = [Version.parse(v) for v in get_schema_map()] if not refresh_all else []
    url = "https://api.github.com/repos/elastic/ecs/releases"
    releases = requests.get(url, timeout=30)

    for release in releases.json():
        version = Version.parse(release.get("tag_name", "").lstrip("v"))

        # we don't ever want beta
        if not version or version < Version.parse("1.0.1") or version in existing:
            continue

        schema_dir = ECS_SCHEMAS_DIR / str(version)
        schema_dir.mkdir(exist_ok=True)

        resp = requests.get(release["zipball_url"], timeout=30)
        with unzip(resp.content) as archive:
            name_list = archive.namelist()
            base = name_list[0]

            members = [f"{base}generated/ecs/ecs_flat.yml", f"{base}generated/ecs/ecs_nested.yml"]
            saved: list[str] = []

            for member in members:
                file_name = Path(member).name

                # load as yaml, save as json
                contents = yaml.safe_load(archive.read(member))
                out_file = file_name.replace(".yml", ".json.gz")

                compressed = gzip_compress(json.dumps(contents, sort_keys=True, cls=DateTimeEncoder))
                new_path = get_etc_path([ECS_NAME, str(version), out_file])
                with new_path.open("wb") as f:
                    _ = f.write(compressed)

                saved.append(out_file)

            if verbose:
                print("Saved files to {}: \n\t- {}".format(schema_dir, "\n\t- ".join(saved)))

    # handle working master separately
    if refresh_master:
        master_ver = requests.get(
            "https://raw.githubusercontent.com/elastic/ecs/master/version",
            timeout=30,
        )
        master_ver = Version.parse(master_ver.text.strip())
        master_schema = requests.get(
            "https://raw.githubusercontent.com/elastic/ecs/master/generated/ecs/ecs_flat.yml",
            timeout=30,
        )
        master_schema = yaml.safe_load(master_schema.text)

        # prepend with underscore so that we can differentiate the fact that this is a working master version
        #   but first clear out any existing masters, since we only ever want 1 at a time
        existing_master = ECS_SCHEMAS_DIR.glob("master_*")
        for m in existing_master:
            shutil.rmtree(m, ignore_errors=True)

        master_dir = f"master_{master_ver}"
        master_dir_path = get_etc_path([ECS_NAME, master_dir])
        master_dir_path.mkdir(exist_ok=True)

        compressed = gzip_compress(json.dumps(master_schema, sort_keys=True, cls=DateTimeEncoder))
        new_path = get_etc_path([ECS_NAME, master_dir, "ecs_flat.json.gz"])
        with new_path.open("wb") as f:
            _ = f.write(compressed)

        if verbose:
            print("Saved files to {}: \n\t- {}".format(master_dir, "ecs_flat.json.gz"))


def download_endpoint_schemas(target: str, overwrite: bool = True) -> None:
    """Download endpoint custom schemas."""

    # location of custom schema YAML files
    url = "https://raw.githubusercontent.com/elastic/endpoint-package/main/custom_schemas"
    r = requests.get(f"{url}/custom_{target}.yml", timeout=30)
    if r.status_code == 404:  # noqa: PLR2004
        r = requests.get(f"{url}/{target}/custom_{target}.yaml", timeout=30)
    r.raise_for_status()
    schema = yaml.safe_load(r.text)[0]
    root_name = schema["name"]
    fields = schema["fields"]
    flattened = {}

    # iterate over nested fields and flatten them
    for f in fields:
        if "multi_fields" in f:
            for mf in f["multi_fields"]:
                flattened[f"{root_name}.{f['name']}.{mf['name']}"] = mf["type"]
        else:
            flattened[f"{root_name}.{f['name']}"] = f["type"]

    # save schema to disk
    ENDPOINT_SCHEMAS_DIR.mkdir(parents=True, exist_ok=True)
    compressed = gzip_compress(json.dumps(flattened, sort_keys=True, cls=DateTimeEncoder))
    new_path = ENDPOINT_SCHEMAS_DIR / f"endpoint_{target}.json.gz"
    if overwrite:
        shutil.rmtree(new_path, ignore_errors=True)
    with new_path.open("wb") as f:
        _ = f.write(compressed)
    print(f"Saved endpoint schema to {new_path}")


@cached
def get_endpoint_schemas() -> dict[str, Any]:
    """Load endpoint schemas."""
    schema: dict[str, Any] = {}
    existing = ENDPOINT_SCHEMAS_DIR.glob("*.json.gz")
    for f in existing:
        schema.update(json.loads(read_gzip(f)))
    return schema

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Custom Schemas management."""
import uuid
from pathlib import Path

import eql
import eql.types
from eql import load_dump, save_dump

from .config import parse_rules_config
from .utils import cached, clear_caches

RULES_CONFIG = parse_rules_config()
RESERVED_SCHEMA_NAMES = ["beats", "ecs", "endgame"]


@cached
def get_custom_schemas(stack_version: str = None) -> dict:
    """Load custom schemas if present."""
    custom_schema_dump = {}

    stack_versions = [stack_version] if stack_version else RULES_CONFIG.stack_schema_map.keys()

    for version in stack_versions:
        stack_schema_map = RULES_CONFIG.stack_schema_map[version]

        for schema, value in stack_schema_map.items():
            if schema not in RESERVED_SCHEMA_NAMES:
                schema_path = Path(value)
                if not schema_path.is_absolute():
                    schema_path = RULES_CONFIG.stack_schema_map_file.parent / value
                if schema_path.is_file():
                    custom_schema_dump.update(eql.utils.load_dump(str(schema_path)))
                else:
                    raise ValueError(f"Custom schema must be a file: {schema_path}")

    return custom_schema_dump


def resolve_schema_path(path: str) -> Path:
    """Helper function to resolve the schema path."""
    path_obj = Path(path)
    return path_obj if path_obj.is_absolute() else RULES_CONFIG.stack_schema_map_file.parent.joinpath(path)


def update_data(index: str, field: str, data: dict, field_type: str = None) -> dict:
    """Update the schema entry with the appropriate index and field."""
    data.setdefault(index, {})[field] = field_type if field_type else "keyword"
    return data


def update_stack_schema_map(stack_schema_map: dict, auto_gen_schema_file: str) -> dict:
    """Update the stack-schema-map.yaml file with the appropriate auto_gen_schema_file location."""
    random_uuid = str(uuid.uuid4())
    auto_generated_id = None
    for version in stack_schema_map:
        key_found = False
        for key, value in stack_schema_map[version].items():
            value_path = resolve_schema_path(value)
            if value_path == Path(auto_gen_schema_file).resolve() and key not in RESERVED_SCHEMA_NAMES:
                auto_generated_id = key
                key_found = True
                break
        if key_found is False:
            if auto_generated_id is None:
                auto_generated_id = random_uuid
            stack_schema_map[version][auto_generated_id] = str(auto_gen_schema_file)
    return stack_schema_map, auto_generated_id, random_uuid


def clean_stack_schema_map(stack_schema_map: dict, auto_generated_id: str, random_uuid: str) -> dict:
    """Clean up the stack-schema-map.yaml file replacing the random UUID with a known key if possible."""
    for version in stack_schema_map:
        if random_uuid in stack_schema_map[version]:
            stack_schema_map[version][auto_generated_id] = stack_schema_map[version].pop(random_uuid)
    return stack_schema_map


def update_auto_generated_schema(index: str, field: str, field_type: str = None):
    """Load custom schemas if present."""
    auto_gen_schema_file = str(RULES_CONFIG.auto_gen_schema_file)
    stack_schema_map_file = str(RULES_CONFIG.stack_schema_map_file)

    # Update autogen schema file
    data = load_dump(auto_gen_schema_file)
    data = update_data(index, field, data, field_type)
    save_dump(data, auto_gen_schema_file)

    # Update the stack-schema-map.yaml file with the appropriate auto_gen_schema_file location
    stack_schema_map = load_dump(stack_schema_map_file)
    stack_schema_map, auto_generated_id, random_uuid = update_stack_schema_map(stack_schema_map, auto_gen_schema_file)
    save_dump(stack_schema_map, stack_schema_map_file)

    # Clean up the stack-schema-map.yaml file replacing the random UUID with the auto_generated_id
    stack_schema_map = load_dump(stack_schema_map_file)
    stack_schema_map = clean_stack_schema_map(stack_schema_map, auto_generated_id, random_uuid)
    save_dump(stack_schema_map, stack_schema_map_file)

    RULES_CONFIG.stack_schema_map = stack_schema_map
    # IMPORTANT must clear cache in order to reload schema
    clear_caches()

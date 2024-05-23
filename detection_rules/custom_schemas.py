# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Custom Schemas management."""
from pathlib import Path

import eql
import eql.types

from .config import parse_rules_config
from .utils import cached

RULES_CONFIG = parse_rules_config()
RESERVED_SCHEMA_NAMES = ["beats", "ecs", "endgame"]


@cached
def get_custom_schemas(stack_version: str) -> dict:
    """Load custom schemas if present."""
    custom_schema_dump = {}
    stack_schema_map = RULES_CONFIG.stack_schema_map[stack_version]

    for schema, value in stack_schema_map.items():
        if schema not in RESERVED_SCHEMA_NAMES:
            schema_path = Path(value)
            if not schema_path.is_absolute():
                schema_path = RULES_CONFIG.stack_schema_map_file.parent / value
            if schema_path.is_file():
                custom_schema_dump.update(eql.utils.load_dump(str(schema_path)))
            elif schema_path.is_dir():
                custom_schema_dump.update(load_schemas_from_dir(schema_path))

    return custom_schema_dump


def load_schemas_from_dir(schema_dir: Path) -> dict:
    """Load all schemas from a directory."""
    schemas_dump = {}
    for file_path in schema_dir.iterdir():
        if file_path.is_file() and file_path.suffix == ".json":
            schemas_dump.update(eql.utils.load_dump(str(file_path)))

    return schemas_dump

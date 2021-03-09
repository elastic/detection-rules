# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from .base import TomlMetadata
from .rta_schema import validate_rta_mapping
from ..semver import Version
from . import definitions

# import all of the schema versions
from .v7_8 import ApiSchema78
from .v7_9 import ApiSchema79
from .v7_10 import ApiSchema710
from .v7_11 import ApiSchema711
from .v7_12 import ApiSchema712

__all__ = (
    "all_schemas",
    "available_versions",
    "downgrade",
    "CurrentSchema",
    "validate_rta_mapping",
    "TomlMetadata",
)

all_schemas = [
    ApiSchema78,
    ApiSchema79,
    ApiSchema710,
    ApiSchema711,
    ApiSchema712,
]
CurrentSchema = all_schemas[-1]
available_versions = [cls.STACK_VERSION for cls in all_schemas]


def downgrade(api_contents: dict, target_version: str):
    """Downgrade a rule to a target stack version."""
    # truncate to (major, minor)
    target_version_str = target_version
    target_version = Version(target_version)[:2]
    versions = set(Version(schema_cls.STACK_VERSION) for schema_cls in all_schemas)
    role = api_contents.get("type")

    check_versioned = "version" in api_contents

    if target_version not in versions:
        raise ValueError(f"Unable to downgrade from {CurrentSchema.STACK_VERSION} to {target_version_str}")

    current_schema = None

    for target_schema in reversed(all_schemas):
        if check_versioned:
            target_schema = target_schema.versioned()

        if current_schema is not None:
            api_contents = current_schema.downgrade(target_schema, api_contents, role)

        current_schema = target_schema
        if Version(current_schema.STACK_VERSION) == target_version:
            break

    return api_contents

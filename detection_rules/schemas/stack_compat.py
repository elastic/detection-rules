# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from dataclasses import Field
from typing import Any

from semver import Version

from detection_rules.misc import cached


@cached
def get_restricted_field(schema_field: Field[Any]) -> tuple[Version | None, Version | None]:
    """Get an optional min and max compatible versions of a field (from a schema or dataclass)."""
    # nested get is to support schema fields being passed directly from dataclass or fields in schema class, since
    # marshmallow_dataclass passes the embedded metadata directly
    min_compat = schema_field.metadata.get("metadata", schema_field.metadata).get("min_compat")
    max_compat = schema_field.metadata.get("metadata", schema_field.metadata).get("max_compat")
    min_compat = Version.parse(min_compat, optional_minor_and_patch=True) if min_compat else None
    max_compat = Version.parse(max_compat, optional_minor_and_patch=True) if max_compat else None
    return min_compat, max_compat


@cached
def get_restricted_fields(schema_fields: list[Field[Any]]) -> dict[str, tuple[Version | None, Version | None]]:
    """Get a list of optional min and max compatible versions of fields (from a schema or dataclass)."""
    restricted: dict[str, tuple[Version | None, Version | None]] = {}
    for _field in schema_fields:
        min_compat, max_compat = get_restricted_field(_field)
        if min_compat or max_compat:
            restricted[_field.name] = (min_compat, max_compat)

    return restricted


@cached
def get_incompatible_fields(
    schema_fields: list[Field[Any]],
    package_version: Version,
) -> dict[str, tuple[Version | None, Version | None]] | None:
    """Get a list of fields that are incompatible with the package version."""
    if not schema_fields:
        return None

    incompatible: dict[str, tuple[Version | None, Version | None]] = {}
    restricted_fields = get_restricted_fields(schema_fields)
    for field_name, values in restricted_fields.items():
        min_compat, max_compat = values

        if (min_compat and package_version < min_compat) or (max_compat and package_version > max_compat):
            incompatible[field_name] = (min_compat, max_compat)

    return incompatible

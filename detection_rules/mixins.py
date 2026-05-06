# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Generic mixin classes."""

import dataclasses
import json
from pathlib import Path
from typing import Any, Literal, get_type_hints

import marshmallow
import marshmallow_dataclass
import marshmallow_dataclass.union_field
import marshmallow_jsonschema  # type: ignore[reportMissingTypeStubs]
import marshmallow_union  # type: ignore[reportMissingTypeStubs]
import typing_inspect  # type: ignore[reportMissingTypeStubs]
from marshmallow import Schema, ValidationError, validates_schema
from marshmallow import fields as marshmallow_fields
from semver import Version

from .config import load_current_package_version
from .schemas import definitions
from .schemas.stack_compat import get_incompatible_fields
from .utils import cached, dict_hash

UNKNOWN_VALUES = Literal["raise", "exclude", "include"]


def _strip_none_from_dict(obj: Any) -> Any:
    """Strip none values from a dict recursively."""
    if isinstance(obj, dict):
        return {key: _strip_none_from_dict(value) for key, value in obj.items() if value is not None}  # type: ignore[reportUnknownVariableType]
    if isinstance(obj, list):
        return [_strip_none_from_dict(o) for o in obj]  # type: ignore[reportUnknownVariableType]
    if isinstance(obj, tuple):
        return tuple(_strip_none_from_dict(list(obj)))  # type: ignore[reportUnknownVariableType]
    return obj


def get_dataclass_required_fields(cls: Any) -> list[str]:
    """Get required fields based on both dataclass and type Annotations."""
    required_fields: list[str] = []
    hints = get_type_hints(cls, include_extras=True)
    marshmallow_schema = marshmallow_dataclass.class_schema(cls)()
    for dc_field in dataclasses.fields(cls):
        hint = hints.get(dc_field.name)
        if not hint:
            continue

        mm_field = marshmallow_schema.fields.get(dc_field.name)  # type: ignore[reportUnknownVariableType,reportUnknownMemberType]
        if mm_field is None:
            continue
        if dc_field.default is not dataclasses.MISSING:
            continue
        if getattr(dc_field, "default_factory", dataclasses.MISSING) is not dataclasses.MISSING:
            continue
        if not typing_inspect.is_optional_type(hint) or mm_field.required is True:  # type: ignore[reportUnknownVariableType]
            required_fields.append(dc_field.name)
    return required_fields


def patch_jsonschema(obj: Any) -> dict[str, Any]:
    """Patch marshmallow-jsonschema output to look more like JSL."""

    def dive(child: dict[str, Any]) -> dict[str, Any]:
        if "$ref" in child:
            name = child["$ref"].split("/")[-1]
            definition = obj["definitions"][name]
            return dive(definition)

        child = child.copy()
        if "default" in child and child["default"] is None:
            child.pop("default")

        child.pop("title", None)
        # marshmallow-jsonschema 0.16+ emits `enumNames: []` alongside enum-translated
        # Literal fields for react-jsonschema-form compatibility; older 0.13 did not,
        # so drop the empty list to keep schemas comparable.
        if child.get("enumNames") == []:
            child.pop("enumNames")
        # marshmallow-jsonschema 0.16+ no longer pairs enums with their underlying
        # `type`. Restore `type: "string"` for string-only enums to match the prior
        # shape so external consumers that key off `type` keep working.
        if (
            "enum" in child
            and "type" not in child
            and child["enum"]
            and all(isinstance(v, str) for v in child["enum"])
        ):
            child["type"] = "string"

        if "anyOf" in child:
            # marshmallow-jsonschema 0.16+ models `Optional[X]` as
            # `anyOf: [<X-schema>, {"type": "null"}]` and tacks an empty placeholder
            # branch (only `default: null` / `title`) on enum-style fields. We dive
            # each branch first so `$ref`s expand and placeholders collapse to `{}`,
            # then drop empty/null-only branches to preserve the previous flat shape.
            dived = [dive(c) for c in child["anyOf"]]
            real_branches = [c for c in dived if c and c != {"type": "null"}]
            had_null_branch = any(c == {"type": "null"} for c in dived)

            if not real_branches:
                # Only null/empty branches remained -- sibling keys (e.g. `enum`)
                # already describe the field, so the bogus anyOf can be dropped.
                child.pop("anyOf")
            elif len(real_branches) == 1 and had_null_branch:
                # Optional<X> -- inline X's keys into the parent, matching the
                # marshmallow-jsonschema 0.13 shape where the wrapper was absent.
                child.pop("anyOf")
                merged = real_branches[0].copy()
                merged.update({k: v for k, v in child.items() if k != "anyOf"})
                child = merged
            else:
                child["anyOf"] = real_branches + ([{"type": "null"}] if had_null_branch else [])

        if isinstance(child.get("type"), list):
            type_vals: list[str] = child["type"]  # type: ignore[reportUnknownVariableType]

            if "null" in type_vals:
                child["type"] = [t for t in type_vals if t != "null"]

            if len(type_vals) == 1:
                child["type"] = child["type"][0]

        if "items" in child:
            child["items"] = dive(child["items"])

        if "properties" in child:
            # .rstrip("_") is workaround for `from_` -> from
            # https://github.com/fuhrysteve/marshmallow-jsonschema/issues/107
            child["properties"] = {k.rstrip("_"): dive(v) for k, v in child["properties"].items()}

        if isinstance(child.get("additionalProperties"), dict):
            # .rstrip("_") is workaround for `from_` -> from
            # https://github.com/fuhrysteve/marshmallow-jsonschema/issues/107
            child["additionalProperties"] = dive(child["additionalProperties"])

        return child

    patched = {"$schema": "http://json-schema.org/draft-04/schema#"}
    patched.update(dive(obj))
    return patched


class BaseSchema(Schema):
    """Base schema for marshmallow dataclasses with unknown."""

    class Meta:  # type: ignore[reportIncompatibleVariableOverride]
        """Meta class for marshmallow schema."""


class MarshmallowDataclassMixin:
    """Mixin class for marshmallow serialization."""

    @classmethod
    @cached
    def __schema(cls, unknown: UNKNOWN_VALUES | None = None) -> Schema:
        """Get the marshmallow schema for the data class"""
        if unknown:
            return recursive_class_schema(cls, unknown=unknown)()
        return marshmallow_dataclass.class_schema(cls)()

    def get(self, key: str, default: Any = None) -> Any:
        """Get a key from the query data without raising attribute errors."""
        return getattr(self, key, default)

    @classmethod
    @cached
    def jsonschema(cls) -> dict[str, Any]:
        """Get the jsonschema representation for this class."""
        jsonschema = PatchedJSONSchema().dump(cls.__schema())  # type: ignore[reportUnknownMemberType]
        return patch_jsonschema(jsonschema)

    @classmethod
    def from_dict(cls, obj: dict[str, Any], unknown: UNKNOWN_VALUES | None = None) -> Any:
        """Deserialize and validate a dataclass from a dict using marshmallow."""
        schema = cls.__schema(unknown=unknown)
        return schema.load(obj)

    def to_dict(self, strip_none_values: bool = True) -> dict[str, Any]:
        """Serialize a dataclass to a dictionary using marshmallow."""
        schema = self.__schema()
        serialized = schema.dump(self)

        if strip_none_values:
            serialized = _strip_none_from_dict(serialized)

        return serialized


def exclude_class_schema(
    cls: type,
    base_schema: type[Schema] = BaseSchema,
    unknown: UNKNOWN_VALUES = marshmallow.EXCLUDE,
    **kwargs: dict[str, Any],
) -> type[Schema]:
    """Get a marshmallow schema for a dataclass with unknown=EXCLUDE."""
    base_schema.Meta.unknown = unknown  # type: ignore[reportAttributeAccessIssue]
    return marshmallow_dataclass.class_schema(cls, base_schema=base_schema, **kwargs)


def recursive_class_schema(
    cls: type,
    base_schema: type[Schema] = BaseSchema,
    unknown: UNKNOWN_VALUES = marshmallow.EXCLUDE,
    **kwargs: dict[str, Any],
) -> type[Schema]:
    """Recursively apply the unknown parameter for nested schemas."""
    schema = exclude_class_schema(cls, base_schema=base_schema, unknown=unknown, **kwargs)
    for field in dataclasses.fields(cls):
        if dataclasses.is_dataclass(field.type):
            nested_cls = field.type
            nested_schema = recursive_class_schema(
                nested_cls,  # type: ignore[reportArgumentType]
                base_schema=base_schema,
                unknown=unknown,
                **kwargs,
            )
            setattr(schema, field.name, nested_schema)
    return schema


class LockDataclassMixin:
    """Mixin class for version and deprecated rules lock files."""

    @classmethod
    @cached
    def __schema(cls) -> Schema:
        """Get the marshmallow schema for the data class"""
        return marshmallow_dataclass.class_schema(cls)()

    def get(self, key: str, default: Any = None) -> Any:
        """Get a key from the query data without raising attribute errors."""
        return getattr(self, key, default)

    @classmethod
    def from_dict(cls, obj: dict[str, Any]) -> Any:
        """Deserialize and validate a dataclass from a dict using marshmallow."""
        schema = cls.__schema()
        try:
            loaded = schema.load(obj)
        except ValidationError as e:
            err_msg = json.dumps(e.normalized_messages(), indent=2)
            raise ValidationError(f"Validation error loading: {cls.__name__}\n{err_msg}") from e
        return loaded

    def to_dict(self, strip_none_values: bool = True) -> dict[str, Any]:
        """Serialize a dataclass to a dictionary using marshmallow."""
        schema = self.__schema()
        serialized: dict[str, Any] = schema.dump(self)

        if strip_none_values:
            serialized = _strip_none_from_dict(serialized)

        return serialized["data"]

    @classmethod
    def load_from_file(cls, lock_file: Path | None = None) -> Any:
        """Load and validate a version lock file."""
        path = getattr(cls, "file_path", lock_file)
        if not path:
            raise ValueError("No file path found")
        contents = json.loads(path.read_text())
        return cls.from_dict({"data": contents})

    def sha256(self) -> definitions.Sha256:
        """Get the sha256 hash of the version lock contents."""
        contents = self.to_dict()
        return dict_hash(contents)

    def save_to_file(self, lock_file: Path | None = None) -> None:
        """Save and validate a version lock file."""
        path = lock_file or getattr(self, "file_path", None)
        if not path:
            raise ValueError("No file path found")
        contents = self.to_dict()
        _ = path.write_text(json.dumps(contents, indent=2, sort_keys=True))


class StackCompatMixin:
    """Mixin to restrict schema compatibility to defined stack versions."""

    @validates_schema
    def validate_field_compatibility(self, data: dict[str, Any], **_: dict[str, Any]) -> None:
        """Verify stack-specific fields are properly applied to schema."""
        package_version = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
        schema_fields = getattr(self, "fields", {})
        incompatible = get_incompatible_fields(list(schema_fields.values()), package_version)
        if not incompatible:
            return

        package_version = load_current_package_version()
        for field, bounds in incompatible.items():
            min_compat, max_compat = bounds
            if data.get(field) is not None:
                raise ValidationError(
                    f'Invalid field: "{field}" for stack version: {package_version}, '
                    f"min compatibility: {min_compat}, max compatibility: {max_compat}"
                )


class PatchedJSONSchema(marshmallow_jsonschema.JSONSchema):
    # Patch marshmallow-jsonschema to support marshmallow-dataclass[union]
    def _get_schema_for_field(self, obj: Any, field: Any) -> Any:
        """Patch marshmallow_jsonschema.base.JSONSchema to support marshmallow-dataclass[union]."""
        if isinstance(field, marshmallow_fields.Raw) and field.allow_none and not field.validate:
            # raw fields shouldn't be type string but type any. bug in marshmallow_dataclass:__init__.py:
            return {"type": ["string", "number", "object", "array", "boolean", "null"]}

        if isinstance(field, marshmallow_dataclass.union_field.Union):
            # convert to marshmallow_union.Union
            # marshmallow 4 removed `name`, `parent`, `root`, and `default_error_messages`
            # from `Field.__init__`; bind the new field to the parent schema after construction.
            new_field = marshmallow_union.Union(
                [subfield for _, subfield in field.union_fields],  # type: ignore[reportUnknownVariableType,reportUnknownMemberType]
                metadata=field.metadata,  # type: ignore[reportUnknownMemberType]
                required=field.required,
                error_messages=field.error_messages,  # type: ignore[reportUnknownMemberType]
                dump_default=field.dump_default,  # type: ignore[reportUnknownMemberType]
                allow_none=field.allow_none,
            )
            new_field._bind_to_schema(field.name, field.parent)  # type: ignore[reportUnknownMemberType]  # noqa: SLF001
            field = new_field
        return super()._get_schema_for_field(obj, field)  # type: ignore[reportUnknownMemberType]

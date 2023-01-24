# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Generic mixin classes."""

from pathlib import Path
from typing import Any, Optional, TypeVar, Type

import json
import marshmallow_dataclass
import marshmallow_dataclass.union_field
import marshmallow_jsonschema
import marshmallow_union
from marshmallow import Schema, ValidationError, fields, validates_schema

from .misc import load_current_package_version
from .schemas import definitions
from .schemas.stack_compat import get_incompatible_fields
from .semver import Version
from .utils import cached, dict_hash

T = TypeVar('T')
ClassT = TypeVar('ClassT')  # bound=dataclass?


def _strip_none_from_dict(obj: T) -> T:
    """Strip none values from a dict recursively."""
    if isinstance(obj, dict):
        return {key: _strip_none_from_dict(value) for key, value in obj.items() if value is not None}
    if isinstance(obj, list):
        return [_strip_none_from_dict(o) for o in obj]
    if isinstance(obj, tuple):
        return tuple(_strip_none_from_dict(list(obj)))
    return obj


def patch_jsonschema(obj: dict) -> dict:
    """Patch marshmallow-jsonschema output to look more like JSL."""

    def dive(child: dict) -> dict:
        if "$ref" in child:
            name = child["$ref"].split("/")[-1]
            definition = obj["definitions"][name]
            return dive(definition)

        child = child.copy()
        if "default" in child and child["default"] is None:
            child.pop("default")

        child.pop("title", None)

        if "anyOf" in child:
            child["anyOf"] = [dive(c) for c in child["anyOf"]]

        elif isinstance(child["type"], list):
            if 'null' in child["type"]:
                child["type"] = [t for t in child["type"] if t != 'null']

            if len(child["type"]) == 1:
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


class MarshmallowDataclassMixin:
    """Mixin class for marshmallow serialization."""

    @classmethod
    @cached
    def __schema(cls: ClassT) -> Schema:
        """Get the marshmallow schema for the data class"""
        return marshmallow_dataclass.class_schema(cls)()

    def get(self, key: str, default: Optional[Any] = None):
        """Get a key from the query data without raising attribute errors."""
        return getattr(self, key, default)

    @classmethod
    @cached
    def jsonschema(cls):
        """Get the jsonschema representation for this class."""
        jsonschema = PatchedJSONSchema().dump(cls.__schema())
        jsonschema = patch_jsonschema(jsonschema)
        return jsonschema

    @classmethod
    def from_dict(cls: Type[ClassT], obj: dict) -> ClassT:
        """Deserialize and validate a dataclass from a dict using marshmallow."""
        schema = cls.__schema()
        return schema.load(obj)

    def to_dict(self, strip_none_values=True) -> dict:
        """Serialize a dataclass to a dictionary using marshmallow."""
        schema = self.__schema()
        serialized: dict = schema.dump(self)

        if strip_none_values:
            serialized = _strip_none_from_dict(serialized)

        return serialized


class LockDataclassMixin:
    """Mixin class for version and deprecated rules lock files."""

    @classmethod
    @cached
    def __schema(cls: ClassT) -> Schema:
        """Get the marshmallow schema for the data class"""
        return marshmallow_dataclass.class_schema(cls)()

    def get(self, key: str, default: Optional[Any] = None):
        """Get a key from the query data without raising attribute errors."""
        return getattr(self, key, default)

    @classmethod
    def from_dict(cls: Type[ClassT], obj: dict) -> ClassT:
        """Deserialize and validate a dataclass from a dict using marshmallow."""
        schema = cls.__schema()
        try:
            loaded = schema.load(obj)
        except ValidationError as e:
            err_msg = json.dumps(e.messages, indent=2)
            raise ValidationError(f'Validation error loading: {cls.__name__}\n{err_msg}') from None
        return loaded

    def to_dict(self, strip_none_values=True) -> dict:
        """Serialize a dataclass to a dictionary using marshmallow."""
        schema = self.__schema()
        serialized: dict = schema.dump(self)

        if strip_none_values:
            serialized = _strip_none_from_dict(serialized)

        return serialized['data']

    @classmethod
    def load_from_file(cls: Type[ClassT], lock_file: Optional[Path] = None) -> ClassT:
        """Load and validate a version lock file."""
        path: Path = getattr(cls, 'file_path', lock_file)
        contents = json.loads(path.read_text())
        loaded = cls.from_dict(dict(data=contents))
        return loaded

    def sha256(self) -> definitions.Sha256:
        """Get the sha256 hash of the version lock contents."""
        contents = self.to_dict()
        return dict_hash(contents)

    def save_to_file(self, lock_file: Optional[Path] = None):
        """Save and validate a version lock file."""
        path: Path = lock_file or getattr(self, 'file_path', None)
        assert path, 'No path passed or set'
        contents = self.to_dict()
        path.write_text(json.dumps(contents, indent=2, sort_keys=True))


class StackCompatMixin:
    """Mixin to restrict schema compatibility to defined stack versions."""

    @validates_schema
    def validate_field_compatibility(self, data: dict, **kwargs):
        """Verify stack-specific fields are properly applied to schema."""
        package_version = Version(load_current_package_version())
        schema_fields = getattr(self, 'fields', {})
        incompatible = get_incompatible_fields(list(schema_fields.values()), package_version)
        if not incompatible:
            return

        package_version = load_current_package_version()
        for field, bounds in incompatible.items():
            min_compat, max_compat = bounds
            if data.get(field) is not None:
                raise ValidationError(f'Invalid field: "{field}" for stack version: {package_version}, '
                                      f'min compatibility: {min_compat}, max compatibility: {max_compat}')


class PatchedJSONSchema(marshmallow_jsonschema.JSONSchema):

    # Patch marshmallow-jsonschema to support marshmallow-dataclass[union]
    def _get_schema_for_field(self, obj, field):
        """Patch marshmallow_jsonschema.base.JSONSchema to support marshmallow-dataclass[union]."""
        if isinstance(field, fields.Raw) and field.allow_none and not field.validate:
            # raw fields shouldn't be type string but type any. bug in marshmallow_dataclass:__init__.py:
            #  if typ is Any:
            #      metadata.setdefault("allow_none", True)
            #      return marshmallow.fields.Raw(**metadata)
            return {"type": ["string", "number", "object", "array", "boolean", "null"]}

        if isinstance(field, marshmallow_dataclass.union_field.Union):
            # convert to marshmallow_union.Union
            field = marshmallow_union.Union([subfield for _, subfield in field.union_fields],
                                            metadata=field.metadata,
                                            required=field.required, name=field.name,
                                            parent=field.parent, root=field.root, error_messages=field.error_messages,
                                            default_error_messages=field.default_error_messages, default=field.default,
                                            allow_none=field.allow_none)

        return super()._get_schema_for_field(obj, field)

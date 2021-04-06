# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Generic mixin classes."""
from typing import TypeVar, Type

import marshmallow_dataclass
import marshmallow_jsonschema
from marshmallow import Schema

from .utils import cached

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

        if isinstance(child["type"], list):
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

    def get(self, key: str):
        """Get a key from the query data without raising attribute errors."""
        return getattr(self, key, None)

    @classmethod
    @cached
    def jsonschema(cls):
        """Get the jsonschema representation for this class."""
        jsonschema = marshmallow_jsonschema.JSONSchema().dump(cls.__schema())
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

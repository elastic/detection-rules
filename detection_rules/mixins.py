# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Generic mixin classes."""
from typing import TypeVar, Type

import marshmallow_dataclass
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


class MarshmallowDataclassMixin:
    """Mixin class for marshmallow serialization."""

    @classmethod
    @cached
    def __schema(cls: ClassT) -> Schema[ClassT]:
        """Get the marshmallow schema for the data class"""
        return marshmallow_dataclass.class_schema(cls)()

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

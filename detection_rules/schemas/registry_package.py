# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Definitions for packages destined for the registry."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Type

from marshmallow import Schema, validate
from marshmallow_dataclass import class_schema

from .definitions import ConditionSemVer, SemVer


@dataclass
class RegistryPackageManifest:
    """Base class for registry packages."""

    categories: List[str]
    conditions: Dict[str, ConditionSemVer]
    description: str
    format_version: SemVer
    icons: list
    license: str
    name: str
    owner: Dict[str, str]
    release: str
    title: str
    type: str
    version: SemVer

    internal: Optional[bool] = None
    policy_templates: list = field(default_factory=list)
    screenshots: list = field(default_factory=list)

    @classmethod
    def get_schema(cls) -> Type[Schema]:
        return class_schema(cls)

    @classmethod
    def from_dict(cls, obj: dict) -> 'RegistryPackageManifest':
        return cls.get_schema()().load(obj)

    def asdict(self) -> dict:
        return self.get_schema()().dump(self)

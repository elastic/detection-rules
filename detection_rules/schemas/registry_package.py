# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Definitions for packages destined for the registry."""

from dataclasses import dataclass, field
from typing import Dict, List, Type

from marshmallow import Schema, validate
from marshmallow_dataclass import class_schema

from .definitions import ConditionSemVer, SemVer


@dataclass
class RegistryPackageManifest:
    """Base class for registry packages."""

    conditions: Dict[str, ConditionSemVer]
    version: SemVer

    categories: List[str] = field(default_factory=lambda: ['security'])
    description: str = 'Rules for the detection engine in the Security application.'
    format_version: SemVer = field(metadata=dict(validate=validate.Equal('1.0.0')), default='1.0.0')
    icons: list = field(default_factory=list)
    internal: bool = True
    license: str = 'basic'
    name: str = 'detection_rules'
    owner: Dict[str, str] = field(default_factory=lambda: dict(github='elastic/protections').copy())
    policy_templates: list = field(default_factory=list)
    release: str = 'experimental'
    screenshots: list = field(default_factory=list)
    title: str = 'Detection rules'
    type: str = 'integration'

    @classmethod
    def get_schema(cls) -> Type[Schema]:
        return class_schema(cls)

    @classmethod
    def from_dict(cls, obj: dict) -> 'RegistryPackageManifest':
        return cls.get_schema()().load(obj)

    def dump(self) -> dict:
        return self.get_schema()().dump(self)

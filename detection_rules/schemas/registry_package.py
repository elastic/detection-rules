# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Definitions for packages destined for the registry."""

import dataclasses
from typing import Dict, Union, Type

import marshmallow_dataclass
from marshmallow import validate

from .definitions import BaseMarshmallowDataclass, ConditionSemVer, SemVer


@marshmallow_dataclass.dataclass
class BaseManifest(BaseMarshmallowDataclass):
    """Base class for registry packages."""

    conditions: Dict[str, ConditionSemVer]
    version: SemVer
    format_version: SemVer

    categories: list = dataclasses.field(default_factory=lambda: ['security'].copy())
    description: str = 'Rules for the detection engine in the Security application.'
    icons: list = dataclasses.field(default_factory=list)
    license: str = 'basic'
    name: str = 'detection_rules'
    owner: dict = dataclasses.field(default_factory=lambda: dict(github='elastic/protections').copy())
    policy_templates: list = dataclasses.field(default_factory=list)
    release: str = 'experimental'
    screenshots: list = dataclasses.field(default_factory=list)
    title: str = 'Detection rules'
    type: str = 'rules'


@marshmallow_dataclass.dataclass
class ManifestV1Dot0(BaseManifest):
    """Integrations registry package schema."""

    format_version: SemVer = dataclasses.field(metadata=dict(validate=validate.Equal('1.0.0')), default='1.0.0')


manifests = [
    ManifestV1Dot0
]
MANIFESTS = [Type[t] for t in manifests]


def get_manifest(format_version: str) -> Union[MANIFESTS]:
    """Retrieve a manifest class by format_version."""
    for manifest in manifests:
        if manifest.format_version == format_version:
            return manifest

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Definitions for packages destined for the registry."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .definitions import ConditionSemVer, SemVer
from ..mixins import MarshmallowDataclassMixin


@dataclass
class ConditionElastic:
    subscription: str


@dataclass
class Condition:
    kibana_version: str = field(metadata={"data_key": "kibana.version"})
    elastic: ConditionElastic


@dataclass
class Icon:
    size: str
    src: str
    type: str


@dataclass
class RegistryPackageManifestBase(MarshmallowDataclassMixin):
    """Base class for registry packages."""

    categories: List[str]
    description: str
    format_version: SemVer
    icons: List[Icon]
    name: str
    owner: Dict[str, str]
    title: str
    type: str
    version: SemVer

    internal: Optional[bool]
    policy_templates: Optional[List[str]]
    screenshots: Optional[List[str]]


@dataclass
class RegistryPackageManifestV1(RegistryPackageManifestBase):
    """Registry packages using elastic-package v1."""

    conditions: Dict[str, ConditionSemVer]
    license: str
    release: str


@dataclass
class RegistryPackageManifestV3(RegistryPackageManifestBase):
    """Registry packages using elastic-package v3."""

    conditions: Condition
    source: Dict[str, str]

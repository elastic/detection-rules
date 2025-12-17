# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Definitions for packages destined for the registry."""

from dataclasses import dataclass, field

from detection_rules.mixins import MarshmallowDataclassMixin
from detection_rules.schemas.definitions import ConditionSemVer, SemVer


@dataclass
class ConditionElastic:
    subscription: str
    capabilities: list[str] | None


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

    categories: list[str]
    description: str
    format_version: SemVer
    icons: list[Icon]
    name: str
    owner: dict[str, str]
    title: str
    type: str
    version: SemVer

    internal: bool | None
    policy_templates: list[str] | None
    screenshots: list[str] | None


@dataclass
class RegistryPackageManifestV1(RegistryPackageManifestBase):
    """Registry packages using elastic-package v1."""

    conditions: dict[str, ConditionSemVer]
    license: str
    release: str


@dataclass
class RegistryPackageManifestV3(RegistryPackageManifestBase):
    """Registry packages using elastic-package v3."""

    conditions: Condition
    source: dict[str, str]

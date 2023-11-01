# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Definitions for packages destined for the registry."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .definitions import ConditionSemVer, SemVer
from ..mixins import MarshmallowDataclassMixin
from marshmallow_dataclass import field_for_schema

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
class RegistryPackageManifest(MarshmallowDataclassMixin):
    """Base class for registry packages using elastic-package v1."""

    categories: List[str]
    conditions: Dict[str, ConditionSemVer]
    description: str
    format_version: SemVer
    icons: List[Icon]
    license: str
    name: str
    owner: Dict[str, str]
    release: str
    title: str
    type: str
    version: SemVer

    internal: Optional[bool] = None
    policy_templates: Optional[list] = None
    screenshots: Optional[list] = None


@dataclass
class RegistryPackageManifestV3(MarshmallowDataclassMixin):
    """Base class for registry packages using elastic-package v3."""

    categories: List[str]
    conditions: Condition
    description: str
    format_version: SemVer
    icons: List[Icon]
    source: Dict[str, str]
    name: str
    owner: Dict[str, str]
    title: str
    type: str
    version: SemVer

    internal: Optional[bool] = None
    policy_templates: Optional[List[str]] = None
    screenshots: Optional[List[str]] = None

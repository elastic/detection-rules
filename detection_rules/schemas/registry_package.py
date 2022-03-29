# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Definitions for packages destined for the registry."""

from dataclasses import dataclass
from typing import Dict, List, Optional

from .definitions import ConditionSemVer, SemVer
from ..mixins import MarshmallowDataclassMixin


@dataclass
class RegistryPackageManifest(MarshmallowDataclassMixin):
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
    policy_templates: Optional[list] = None
    screenshots: Optional[list] = None

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Dataclasses for Action."""
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .mixins import MarshmallowDataclassMixin
from .schemas import definitions


@dataclass(frozen=True)
class ActionMeta(MarshmallowDataclassMixin):
    """Data stored in an exception's [metadata] section of TOML."""
    creation_date: definitions.Date
    rule_id: List[definitions.UUIDString]
    rule_name: str
    updated_date: definitions.Date

    # Optional fields
    deprecation_date: Optional[definitions.Date]
    comments: Optional[str]
    maturity: Optional[definitions.Maturity]


@dataclass
class Action(MarshmallowDataclassMixin):
    """Data object for rule Action."""
    @dataclass
    class ActionParams:
        """Data object for rule Action params."""
        body: str

    action_type_id: definitions.ActionTypeId
    group: str
    params: ActionParams
    id: Optional[str]
    frequency: Optional[dict]
    alerts_filter: Optional[dict]


@dataclass(frozen=True)
class TOMLActionContents(MarshmallowDataclassMixin):
    """Object for action from TOML file."""
    metadata: ActionMeta
    actions: List[Action]


@dataclass(frozen=True)
class TOMLAction:
    """Object for action from TOML file."""
    contents: TOMLActionContents
    path: Path

    @property
    def name(self):
        return self.contents.metadata.rule_name

    @property
    def id(self):
        return self.contents.metadata.rule_id

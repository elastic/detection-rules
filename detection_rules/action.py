# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Dataclasses for Action."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .mixins import MarshmallowDataclassMixin
from .schemas import definitions


@dataclass(frozen=True)
class ActionMeta(MarshmallowDataclassMixin):
    """Data stored in an exception's [metadata] section of TOML."""

    creation_date: definitions.Date
    rule_id: list[definitions.UUIDString]
    rule_name: str
    updated_date: definitions.Date

    # Optional fields
    deprecation_date: definitions.Date | None = None
    comments: str | None = None
    maturity: definitions.Maturity | None = None


@dataclass(frozen=True)
class Action(MarshmallowDataclassMixin):
    """Data object for rule Action."""

    @dataclass
    class ActionParams:
        """Data object for rule Action params."""

        body: str

    action_type_id: definitions.ActionTypeId
    group: str
    params: ActionParams

    id: str | None = None
    frequency: dict[str, Any] | None = None
    alerts_filter: dict[str, Any] | None = None


@dataclass(frozen=True)
class TOMLActionContents(MarshmallowDataclassMixin):
    """Object for action from TOML file."""

    metadata: ActionMeta
    actions: list[Action]


@dataclass(frozen=True)
class TOMLAction:
    """Object for action from TOML file."""

    contents: TOMLActionContents
    path: Path

    @property
    def name(self) -> str:
        return self.contents.metadata.rule_name

    @property
    def id(self) -> list[definitions.UUIDString]:
        return self.contents.metadata.rule_id

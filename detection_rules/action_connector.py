# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Dataclasses for Action."""
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import pytoml
from marshmallow import EXCLUDE

from .mixins import MarshmallowDataclassMixin
from .schemas import definitions
from .config import parse_rules_config

RULES_CONFIG = parse_rules_config()


@dataclass(frozen=True)
class ActionConnectorMeta(MarshmallowDataclassMixin):
    """Data stored in an Action Connector's [metadata] section of TOML."""

    creation_date: definitions.Date
    action_connector_name: str
    rule_ids: List[definitions.UUIDString]
    rule_names: List[str]
    updated_date: definitions.Date

    # Optional fields
    deprecation_date: Optional[definitions.Date]
    comments: Optional[str]
    maturity: Optional[definitions.Maturity]


@dataclass
class ActionConnector(MarshmallowDataclassMixin):
    """Data object for rule Action Connector."""

    id: str
    attributes: dict
    frequency: Optional[dict]
    managed: Optional[bool]
    type: Optional[str]
    references: Optional[List]


@dataclass(frozen=True)
class TOMLActionConnectorContents(MarshmallowDataclassMixin):
    """Object for action connector from TOML file."""

    metadata: ActionConnectorMeta
    action_connectors: List[ActionConnector]

    @classmethod
    def from_action_connector_dict(
        cls,
        actions_dict: dict,
        rule_list: dict,
    ) -> "TOMLActionConnectorContents":
        """Create a TOMLActionContents from a kibana rule resource."""
        rule_ids = []
        rule_names = []

        for rule in rule_list:
            rule_ids.append(rule["id"])
            rule_names.append(rule["name"])

        # Format date to match schema
        creation_date = datetime.strptime(actions_dict["created_at"], "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y/%m/%d")
        updated_date = datetime.strptime(actions_dict["updated_at"], "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y/%m/%d")
        metadata = {
            "creation_date": creation_date,
            "rule_ids": rule_ids,
            "rule_names": rule_names,
            "updated_date": updated_date,
            "action_connector_name": f"Action Connector {actions_dict.get('id')}",
        }

        return cls.from_dict({"metadata": metadata, "action_connectors": [actions_dict]}, unknown=EXCLUDE)

    def to_api_format(self) -> List[dict]:
        """Convert the TOML Action Connector to the API format."""
        converted = []

        for action in self.action_connectors:
            converted.append(action.to_dict())
        return converted


@dataclass(frozen=True)
class TOMLActionConnector:
    """Object for action connector from TOML file."""

    contents: TOMLActionConnectorContents
    path: Path

    @property
    def name(self):
        return self.contents.metadata.action_connector_name

    def save_toml(self):
        """Save the action to a TOML file."""
        assert self.path is not None, f"Can't save action for {self.name} without a path"
        # Check if self.path has a .toml extension
        path = self.path
        if path.suffix != ".toml":
            # If it doesn't, add one
            path = path.with_suffix(".toml")
        with path.open("w") as f:
            contents_dict = self.contents.to_dict()
            # Sort the dictionary so that 'metadata' is at the top
            sorted_dict = dict(sorted(contents_dict.items(), key=lambda item: item[0] != "metadata"))
            pytoml.dump(sorted_dict, f)


def parse_action_connector_results_from_api(results: List[dict]) -> tuple[List[dict], List[dict]]:
    """Parse the results from the API to split into action connector results and non-actions."""
    action_results = []
    non_action_results = []
    for result in results:
        if result.get("type") != "action":
            non_action_results.append(result)
        else:
            action_results.append(result)

    return action_results, non_action_results

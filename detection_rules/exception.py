# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.
"""Rule exceptions data."""
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Union

import toml
from marshmallow import ValidationError, validates_schema

from .mixins import MarshmallowDataclassMixin
from .rule import TOMLRuleContents
from .schemas import definitions

TIME_NOW = time.strftime("%Y/%m/%d")

# https://www.elastic.co/guide/en/security/current/exceptions-api-overview.html


@dataclass(frozen=True)
class ExceptionMeta(MarshmallowDataclassMixin):
    """Data stored in an exception's [metadata] section of TOML."""

    creation_date: definitions.Date
    rule_id: definitions.UUIDString
    rule_name: str
    updated_date: definitions.Date

    # Optional fields
    deprecation_date: Optional[definitions.Date]
    comments: Optional[str]
    maturity: Optional[definitions.Maturity]


@dataclass(frozen=True)
class BaseExceptionItemEntry(MarshmallowDataclassMixin):
    """Shared object between nested and non-nested exception items."""

    field: str
    type: definitions.ExceptionEntryType


@dataclass(frozen=True)
class NestedExceptionItemEntry(BaseExceptionItemEntry, MarshmallowDataclassMixin):
    """Nested exception item entry."""

    entries: List["ExceptionItemEntry"]

    @validates_schema
    def validate_nested_entry(self, data: dict, **kwargs):
        """More specific validation."""
        if data.get("list") is not None:
            raise ValidationError("Nested entries cannot define a list")


@dataclass(frozen=True)
class ExceptionItemEntry(BaseExceptionItemEntry, MarshmallowDataclassMixin):
    """Exception item entry."""

    @dataclass(frozen=True)
    class ListObject:
        """List object for exception item entry."""

        id: definitions.UUIDString
        type: definitions.EsDataTypes

    list: Optional[ListObject]
    operator: definitions.ExceptionEntryOperator
    value: Optional[Union[str, List[str]]]

    @validates_schema
    def validate_entry(self, data: dict, **kwargs):
        """Validate the entry based on its type."""
        value = data.get("value", "")
        if data["type"] in ("exists", "list") and value is not None:
            raise ValidationError(f'Entry of type {data["type"]} cannot have a value')
        elif data["type"] in ("match", "wildcard") and not isinstance(value, str):
            raise ValidationError(f'Entry of type {data["type"]} must have a string value')
        elif data["type"] == "match_any" and not isinstance(value, list):
            raise ValidationError(f'Entry of type {data["type"]} must have a list of strings as a value')


@dataclass(frozen=True)
class ExceptionItem(MarshmallowDataclassMixin):
    """Base exception item."""

    field: str
    operator: str
    type: str
    value: str


@dataclass(frozen=True)
class EndpointException(ExceptionItem, MarshmallowDataclassMixin):
    """Endpoint exception item."""

    _tags: List[definitions.ExceptionItemEndpointTags]

    @validates_schema
    def validate_endpoint(self, data: dict, **kwargs):
        """Validate the endpoint exception."""
        for entry in data["entries"]:
            if entry["operator"] == "excluded":
                raise ValidationError("Endpoint exceptions cannot have an `excluded` operator")


@dataclass(frozen=True)
class DetectionException(ExceptionItem, MarshmallowDataclassMixin):
    """Detection exception item."""

    expire_time: Optional[str]  # fields.DateTime]  # maybe this is isoformat?


@dataclass(frozen=True)
class ExceptionContainer(MarshmallowDataclassMixin):
    """Exception container."""

    description: str
    id: str
    list_id: str
    name: str
    entries: List[DetectionException]  # Union[DetectionException, EndpointException]]

    os_types: Optional[List[str]]
    namespace_type: Optional[definitions.ExceptionNamespaceType]
    _version: Optional[str]
    tags: Optional[List[str]]
    type: definitions.ExceptionContainerType
    comments: Optional[List[str]]
    created_at: Optional[str]
    created_by: Optional[str]
    updated_at: Optional[str]
    updated_by: Optional[str]
    item_id: Optional[str]  # api sets field when not provided
    tie_breaker_id: Optional[str]

    def to_rule_entry(self) -> dict:
        """Returns a dict of the format required in rule.exception_list."""
        # requires KSO id to be consider valid structure
        return dict(namespace_type=self.namespace_type, type=self.type, list_id=self.list_id)


@dataclass(frozen=True)
class TOMLExceptionContents(MarshmallowDataclassMixin):
    """Data stored in an exception file."""

    metadata: ExceptionMeta
    exceptions: List[ExceptionContainer]

    @classmethod
    def from_rule_contents(
        cls,
        rule: TOMLRuleContents,
        exception_data: List[dict],
        creation_date: str = TIME_NOW,
        updated_date: str = TIME_NOW,
    ) -> "TOMLExceptionContents":
        """Create a TOMLExceptionContents from a kibana rule resource."""
        metadata = {
            "creation_date": rule.metadata.creation_date,
            "rule_id": rule.id,
            "rule_name": rule.name,
            "updated_date": rule.metadata.updated_date,
        }
        contents = cls.from_dict({"metadata": metadata, "exceptions": exception_data})
        return contents


@dataclass(frozen=True)
class TOMLException:
    """TOML exception object."""

    contents: TOMLExceptionContents
    path: Optional[Path] = None

    @property
    def rule_name(self):
        """Return the exception name."""
        return self.contents.metadata.rule_name

    @property
    def rule_id(self):
        """Return the exception ID."""
        return self.contents.metadata.rule_id

    def save_toml(self):
        """Save the exception to a TOML file."""
        assert self.path is not None, f"Can't save exception {self.contents.name} without a path"
        # Check if self.path has a .toml extension
        path = self.path
        if path.suffix != ".toml":
            # If it doesn't, add one
            path = path.with_suffix(".toml")
        with path.open("w") as f:
            toml.dump(self.contents.to_dict(), f)

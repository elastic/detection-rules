# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.
"""Rule exceptions data."""
from dataclasses import dataclass
from pathlib import Path
from typing import List, Literal, Optional, Union

from marshmallow import validates_schema, ValidationError

from .mixins import MarshmallowDataclassMixin
from .schemas import definitions


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
    entries: List['ExceptionItemEntry']

    @validates_schema
    def validate_nested_entry(self, data: dict, **kwargs):
        """More specific validation."""
        if data.get('list') is not None:
            raise ValidationError('Nested entries cannot define a list')


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
        value = data.get('value', '')
        if data['type'] in ('exists', 'list') and value is not None:
            raise ValidationError(f'Entry of type {data["type"]} cannot have a value')
        elif data['type'] in ('match', 'wildcard') and not isinstance(value, str):
            raise ValidationError(f'Entry of type {data["type"]} must have a string value')
        elif data['type'] == 'match_any' and not isinstance(value, list):
            raise ValidationError(f'Entry of type {data["type"]} must have a list of strings as a value')


@dataclass(frozen=True)
class ExceptionItem(MarshmallowDataclassMixin):
    """Base exception item."""
    @dataclass(frozen=True)
    class Comment:
        """Comment object for exception item."""
        comment: str

    comments: List[Optional[Comment]]
    description: str
    entries: List[Union[ExceptionItemEntry, NestedExceptionItemEntry]]
    list_id: str
    item_id: Optional[str]  # api sets field when not provided
    meta: Optional[dict]
    name: str
    namespace_type: Optional[definitions.ExceptionNamespaceType]  # defaults to "single" if not provided
    tags: Optional[List[str]]
    type: Literal['simple']


@dataclass(frozen=True)
class EndpointException(ExceptionItem, MarshmallowDataclassMixin):
    """Endpoint exception item."""
    _tags: List[definitions.ExceptionItemEndpointTags]

    @validates_schema
    def validate_endpoint(self, data: dict, **kwargs):
        """Validate the endpoint exception."""
        for entry in data['entries']:
            if entry['operator'] == "excluded":
                raise ValidationError("Endpoint exceptions cannot have an `excluded` operator")


@dataclass(frozen=True)
class DetectionException(ExceptionItem, MarshmallowDataclassMixin):
    """Detection exception item."""
    expire_time: Optional[str]  # fields.DateTime]  # maybe this is isoformat?


@dataclass(frozen=True)
class ExceptionContainer(MarshmallowDataclassMixin):
    """Exception container."""
    description: str
    list_id: Optional[str]
    meta: Optional[dict]
    name: str
    namespace_type: Optional[definitions.ExceptionNamespaceType]
    tags: Optional[List[str]]
    type: definitions.ExceptionContainerType

    def to_rule_entry(self) -> dict:
        """Returns a dict of the format required in rule.exception_list."""
        # requires KSO id to be consider valid structure
        return dict(namespace_type=self.namespace_type, type=self.type, list_id=self.list_id)


@dataclass(frozen=True)
class Data(MarshmallowDataclassMixin):
    """Data stored in an exception's [exception] section of TOML."""
    container: ExceptionContainer
    items: List[DetectionException]  # Union[DetectionException, EndpointException]]


@dataclass(frozen=True)
class TOMLExceptionContents(MarshmallowDataclassMixin):
    """Data stored in an exception file."""
    metadata: ExceptionMeta
    exceptions: List[Data]


@dataclass(frozen=True)
class TOMLException:
    """TOML exception object."""
    contents: TOMLExceptionContents
    path: Optional[Path] = None

    @property
    def name(self):
        return self.contents.metadata.rule_name

    @property
    def id(self):
        return self.contents.metadata.rule_id

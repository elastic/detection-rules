# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.
"""Rule exceptions data."""
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Literal, Optional, Union

import pytoml
from marshmallow import EXCLUDE, ValidationError, validates_schema
from marshmallow_dataclass import class_schema

from .mixins import MarshmallowDataclassMixin
from .schemas import definitions


# https://www.elastic.co/guide/en/security/current/exceptions-api-overview.html

@dataclass(frozen=True)
class ExceptionMeta(MarshmallowDataclassMixin):
    """Data stored in an exception's [metadata] section of TOML."""
    creation_date: definitions.Date
    rule_ids: List[definitions.UUIDString]
    rule_names: List[str]
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

    @classmethod
    def from_exceptions_dict(
        cls,
        exceptions_dict: dict,
        rule_list: list[dict],
    ) -> "TOMLExceptionContents":
        """Create a TOMLExceptionContents from a kibana rule resource."""
        rule_ids = []
        rule_names = []

        for rule in rule_list:
            rule_ids.append(rule["id"])
            rule_names.append(rule["name"])

        # Format date to match schema
        creation_date = datetime.strptime(exceptions_dict["container"]["created_at"], "%Y-%m-%dT%H:%M:%S.%fZ").strftime(
            "%Y/%m/%d"
        )
        updated_date = datetime.strptime(exceptions_dict["container"]["updated_at"], "%Y-%m-%dT%H:%M:%S.%fZ").strftime(
            "%Y/%m/%d"
        )
        metadata = {
            "creation_date": creation_date,
            "rule_ids": rule_ids,
            "rule_names": rule_names,
            "updated_date": updated_date,
        }

        return cls.from_dict({"metadata": metadata, "exceptions": [exceptions_dict]}, unknown=EXCLUDE)


@dataclass(frozen=True)
class TOMLException:
    """TOML exception object."""
    contents: TOMLExceptionContents
    path: Optional[Path] = None

    @property
    def name(self):
        """Return the name of the exception."""
        return self.contents.metadata.rule_name

    @property
    def id(self):
        """Return the rule ID of the exception."""
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
            contents_dict = self.contents.to_dict()
            # Sort the dictionary so that 'metadata' is at the top
            sorted_dict = dict(sorted(contents_dict.items(), key=lambda item: item[0] != "metadata"))
            pytoml.dump(sorted_dict, f)


def parse_exceptions_results_from_api(
    results: List[dict], skip_errors: bool = False
) -> tuple[dict, dict, List[str], List[dict]]:
    """Parse exceptions results from the API into containers and items."""
    exceptions_containers = {}
    exceptions_items = {}
    errors = []
    unparsed_results = []

    # Create schemas for your dataclasses
    ExceptionContainerSchema = class_schema(ExceptionContainer)()  # noqa F821
    DetectionExceptionSchema = class_schema(DetectionException)()  # noqa F821

    for res in results:
        try:
            # Try to load the data into the ExceptionContainer schema
            ExceptionContainerSchema.load(res, unknown=EXCLUDE)
            exceptions_containers[res.get("list_id")] = res
        except ValidationError:
            try:
                # Try to load the data into the DetectionException schema
                DetectionExceptionSchema.load(res, unknown=EXCLUDE)
                list_id = res.get("list_id")
                if list_id not in exceptions_items:
                    exceptions_items[list_id] = []
                exceptions_items[list_id].append(res)
            except Exception:
                if skip_errors:
                    # This likely means the data is not an exception and is either
                    # an action list or rule data
                    unparsed_results.append(res)
                    continue
                raise

    return exceptions_containers, exceptions_items, errors, unparsed_results

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.
"""Rule exceptions data."""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, get_args

import pytoml  # type: ignore[reportMissingTypeStubs]
from marshmallow import EXCLUDE, ValidationError, validates_schema

from .config import parse_rules_config
from .mixins import MarshmallowDataclassMixin
from .schemas import definitions

RULES_CONFIG = parse_rules_config()

# https://www.elastic.co/guide/en/security/current/exceptions-api-overview.html


@dataclass(frozen=True)
class ExceptionMeta(MarshmallowDataclassMixin):
    """Data stored in an exception's [metadata] section of TOML."""

    creation_date: definitions.Date
    list_name: str
    rule_ids: list[definitions.UUIDString]
    rule_names: list[str]
    updated_date: definitions.Date

    # Optional fields
    deprecation_date: definitions.Date | None = None
    comments: str | None = None
    maturity: definitions.Maturity | None = None


@dataclass(frozen=True)
class BaseExceptionItemEntry(MarshmallowDataclassMixin):
    """Shared object between nested and non-nested exception items."""

    field: str
    type: definitions.ExceptionEntryType


@dataclass(frozen=True)
class NestedExceptionItemEntry(BaseExceptionItemEntry, MarshmallowDataclassMixin):
    """Nested exception item entry."""

    entries: list["ExceptionItemEntry"]

    @validates_schema
    def validate_nested_entry(self, data: dict[str, Any], **_: Any) -> None:
        """More specific validation."""
        if data.get("list"):
            raise ValidationError("Nested entries cannot define a list")


@dataclass(frozen=True)
class ExceptionItemEntry(BaseExceptionItemEntry, MarshmallowDataclassMixin):
    """Exception item entry."""

    @dataclass(frozen=True)
    class ListObject:
        """List object for exception item entry."""

        id: str
        type: definitions.EsDataTypes

    operator: definitions.ExceptionEntryOperator
    list_vals: ListObject | None = None
    value: str | None | list[str] = None

    @validates_schema
    def validate_entry(self, data: dict[str, Any], **_: Any) -> None:
        """Validate the entry based on its type."""
        value = data.get("value", "")
        if data["type"] in ("exists", "list") and value is not None:
            raise ValidationError(f"Entry of type {data['type']} cannot have a value")
        if data["type"] in ("match", "wildcard") and not isinstance(value, str):
            raise ValidationError(f"Entry of type {data['type']} must have a string value")
        if data["type"] == "match_any" and not isinstance(value, list):
            raise ValidationError(f"Entry of type {data['type']} must have a list of strings as a value")


@dataclass(frozen=True)
class ExceptionItem(MarshmallowDataclassMixin):
    """Base exception item."""

    @dataclass(frozen=True)
    class Comment:
        """Comment object for exception item."""

        comment: str

    comments: list[Comment | None]
    description: str
    entries: list[ExceptionItemEntry | NestedExceptionItemEntry]
    list_id: str
    item_id: str | None  # api sets field when not provided
    meta: dict[str, Any] | None
    name: str
    namespace_type: definitions.ExceptionNamespaceType | None  # defaults to "single" if not provided
    tags: list[str] | None
    type: definitions.ExceptionItemType


@dataclass(frozen=True)
class EndpointException(ExceptionItem, MarshmallowDataclassMixin):
    """Endpoint exception item."""

    _tags: list[definitions.ExceptionItemEndpointTags]

    @validates_schema
    def validate_endpoint(self, data: dict[str, Any], **_: Any) -> None:
        """Validate the endpoint exception."""
        for entry in data["entries"]:
            if entry["operator"] == "excluded":
                raise ValidationError("Endpoint exceptions cannot have an `excluded` operator")


@dataclass(frozen=True)
class DetectionException(ExceptionItem, MarshmallowDataclassMixin):
    """Detection exception item."""

    expire_time: str | None  # fields.DateTime]  # maybe this is isoformat?


@dataclass(frozen=True)
class ExceptionContainer(MarshmallowDataclassMixin):
    """Exception container."""

    description: str
    list_id: str | None
    meta: dict[str, Any] | None
    name: str
    namespace_type: definitions.ExceptionNamespaceType | None
    tags: list[str] | None
    type: definitions.ExceptionContainerType

    def to_rule_entry(self) -> dict[str, Any]:
        """Returns a dict of the format required in rule.exception_list."""
        # requires KSO id to be consider valid structure
        return {"namespace_type": self.namespace_type, "type": self.type, "list_id": self.list_id}


@dataclass(frozen=True)
class Data(MarshmallowDataclassMixin):
    """Data stored in an exception's [exception] section of TOML."""

    container: ExceptionContainer
    items: list[DetectionException] | None


@dataclass(frozen=True)
class TOMLExceptionContents(MarshmallowDataclassMixin):
    """Data stored in an exception file."""

    metadata: ExceptionMeta
    exceptions: list[Data]

    @classmethod
    def from_exceptions_dict(
        cls, exceptions_dict: dict[str, Any], rule_list: list[dict[str, Any]]
    ) -> "TOMLExceptionContents":
        """Create a TOMLExceptionContents from a kibana rule resource."""
        rule_ids: list[str] = []
        rule_names: list[str] = []

        for rule in rule_list:
            rule_ids.append(rule["id"])
            rule_names.append(rule["name"])

        # Format date to match schema
        container = exceptions_dict["container"]
        creation_date = datetime.strptime(container["created_at"], "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y/%m/%d")  # noqa: DTZ007
        updated_date = datetime.strptime(container["updated_at"], "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y/%m/%d")  # noqa: DTZ007
        metadata = {
            "creation_date": creation_date,
            "list_name": exceptions_dict["container"]["name"],
            "rule_ids": rule_ids,
            "rule_names": rule_names,
            "updated_date": updated_date,
        }

        return cls.from_dict({"metadata": metadata, "exceptions": [exceptions_dict]}, unknown=EXCLUDE)

    def to_api_format(self) -> list[dict[str, Any]]:
        """Convert the TOML Exception to the API format."""
        converted: list[dict[str, Any]] = []

        for exception in self.exceptions:
            converted.append(exception.container.to_dict())
            if exception.items:
                converted.extend([item.to_dict() for item in exception.items])

        return converted


@dataclass(frozen=True)
class TOMLException:
    """TOML exception object."""

    contents: TOMLExceptionContents
    path: Path | None = None

    @property
    def name(self) -> str:
        """Return the name of the exception list."""
        return self.contents.metadata.list_name

    def save_toml(self) -> None:
        """Save the exception to a TOML file."""
        if not self.path:
            raise ValueError(f"Can't save exception {self.name} without a path")
        # Check if self.path has a .toml extension
        path = self.path
        if path.suffix != ".toml":
            # If it doesn't, add one
            path = path.with_suffix(".toml")
        with path.open("w") as f:
            contents_dict = self.contents.to_dict()
            # Sort the dictionary so that 'metadata' is at the top
            sorted_dict = dict(sorted(contents_dict.items(), key=lambda item: item[0] != "metadata"))
            pytoml.dump(sorted_dict, f)  # type: ignore[reportUnknownMemberType]


def parse_exceptions_results_from_api(
    results: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any], list[str], list[dict[str, Any]]]:
    """Parse exceptions results from the API into containers and items."""
    exceptions_containers: dict[str, Any] = {}
    exceptions_items: dict[str, list[Any]] = defaultdict(list)
    unparsed_results: list[dict[str, Any]] = []

    for result in results:
        result_type = result.get("type")
        list_id = result.get("list_id")

        if result_type and list_id:
            if result_type in get_args(definitions.ExceptionContainerType):
                exceptions_containers[list_id] = result
            elif result_type in get_args(definitions.ExceptionItemType):
                exceptions_items[list_id].append(result)
        else:
            unparsed_results.append(result)

    return exceptions_containers, exceptions_items, [], unparsed_results


def build_exception_objects(  # noqa: PLR0913
    exceptions_containers: dict[str, Any],
    exceptions_items: dict[str, Any],
    exception_list_rule_table: dict[str, Any],
    exceptions_directory: Path | None,
    save_toml: bool = False,
    skip_errors: bool = False,
    verbose: bool = False,
) -> tuple[list[TOMLException], list[str], list[str]]:
    """Build TOMLException objects from a list of exception dictionaries."""
    output: list[str] = []
    errors: list[str] = []
    toml_exceptions: list[TOMLException] = []
    for container in exceptions_containers.values():
        try:
            list_id = container["list_id"]
            items = exceptions_items[list_id]
            contents = TOMLExceptionContents.from_exceptions_dict(
                {"container": container, "items": items},
                exception_list_rule_table[list_id],
            )
            filename = f"{list_id}_exceptions.toml"
            if RULES_CONFIG.exception_dir is None and not exceptions_directory:
                raise FileNotFoundError(  # noqa: TRY301
                    "No Exceptions directory is specified. Please specify either in the config or CLI."
                )
            exceptions_path = (
                Path(exceptions_directory) / filename if exceptions_directory else RULES_CONFIG.exception_dir / filename
            )
            if verbose:
                output.append(f"[+] Building exception(s) for {exceptions_path}")
            e_object = TOMLException(
                contents=contents,
                path=exceptions_path,
            )
            if save_toml:
                e_object.save_toml()
            toml_exceptions.append(e_object)

        except Exception as e:
            if skip_errors:
                output.append(f"- skipping exceptions export - {type(e).__name__}")
                if not exceptions_directory:
                    errors.append(f"- no exceptions directory found - {e}")
                else:
                    errors.append(f"- exceptions export - {e}")
                continue
            raise

    return toml_exceptions, output, errors

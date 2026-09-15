# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""ES|QL query parsing and schema helpers backed by the offline python-esql parser."""

import fnmatch
import re
from dataclasses import dataclass
from typing import Any, cast

import esql
import kql  # type: ignore[reportMissingTypeStubs]

from . import ecs
from .config import CUSTOM_RULES_DIR, load_current_package_version, parse_rules_config

RULES_CONFIG = parse_rules_config()

# Fleet package names are the first dotted segment of a data stream index pattern.
INDEX_PACKAGE_REGEX = re.compile(r"^(?:logs|metrics|traces)-([a-zA-Z0-9_]+)", re.IGNORECASE)

# Some datasets are shipped under a name that differs from their Fleet package name.
DATASET_PACKAGE_ALIASES = {"googlecloud": "gcp"}


@dataclass
class EventDataset:
    """Class for ESQL event dataset integrations."""

    package: str
    integration: str

    def __post_init__(self) -> None:
        self.package = DATASET_PACKAGE_ALIASES.get(self.package, self.package)

    def __str__(self) -> str:
        return f"{self.package}.{self.integration}"


def esql_parser_config(min_stack_version: str | None = None) -> Any:
    """Build the python-esql parser configuration used for detection rules."""

    def parse_nested_kql(text: str) -> Any:
        """Validate nested KQL(\"\"\"...\"\"\") payloads with the repo's KQL parser."""
        return kql.parse(text, normalize_kql_keywords=RULES_CONFIG.normalize_kql_keywords)  # type: ignore[reportUnknownMemberType]

    stack_version = min_stack_version or load_current_package_version()
    return esql.ParserConfig(min_stack_version=stack_version, kql_parse=parse_nested_kql)


def parse_esql_query(query: str, min_stack_version: str | None = None) -> Any:
    """Parse an ES|QL query without enforcing a schema."""
    with esql_parser_config(min_stack_version), esql.Schema({}, allow_missing=True):
        return esql.parse_query(query)


def get_esql_query_event_dataset_integrations(query: str, tree: Any | None = None) -> list[EventDataset]:
    """Extract event.dataset and data_stream.dataset integrations from an ES|QL query."""
    parsed = tree if tree is not None else parse_esql_query(query)
    return [EventDataset(package=d.package, integration=d.integration) for d in esql.get_event_datasets(parsed)]


def index_patterns_match(left: str, right: str) -> bool:
    """Return whether two index patterns can match the same index name."""
    return left == right or fnmatch.fnmatch(left, right) or fnmatch.fnmatch(right, left)


def infer_packages_from_indices(indices: list[str]) -> list[str]:
    """Infer Fleet package names from explicit ES|QL FROM patterns."""
    packages: list[str] = []
    for index in indices:
        match = INDEX_PACKAGE_REGEX.match(index)
        if match:
            package = match.group(1).lower()
            if package not in packages:
                packages.append(package)
    return packages


def collect_index_field_schemas(indices: list[str]) -> dict[str, Any]:
    """Collect non-ECS, custom, and Endpoint fields matching the query's FROM sources."""
    fields: dict[str, Any] = {}
    non_ecs = ecs.get_non_ecs_schema()
    for index in indices:
        fields.update(ecs.flatten(ecs.get_index_schema(index)))
        for pattern, index_fields in non_ecs.items():
            if index_patterns_match(index, pattern):
                fields.update(index_fields)
        if CUSTOM_RULES_DIR:
            fields.update(ecs.flatten(ecs.get_custom_index_schema(index)))
    fields.update(ecs.flatten(ecs.get_endpoint_schemas()))
    return fields


def stream_matches_indices(package: str, dataset: str, indices: list[str]) -> bool:
    """Return whether a Fleet package stream can back one of the query's FROM sources."""
    if not indices:
        return True
    candidates = (
        f"logs-{package}.{dataset}*",
        f"metrics-{package}.{dataset}*",
        f"traces-{package}.{dataset}*",
        f"logs-{package}.events.{dataset}*",
    )
    return any(index_patterns_match(index, candidate) for index in indices for candidate in candidates)


def collect_package_fields_for_indices(
    package_schema: dict[str, Any],
    package: str,
    indices: list[str],
    integration: str | None = None,
) -> dict[str, Any]:
    """Collect only the package stream fields that match the query's FROM sources."""
    if integration is not None:
        fields = package_schema.get(integration)
        if isinstance(fields, dict) and stream_matches_indices(package, integration, indices):
            return dict(cast("dict[str, Any]", fields))
        return {}

    matching_fields: dict[str, Any] = {}
    for dataset, dataset_fields in package_schema.items():
        if dataset != "jobs" and isinstance(dataset_fields, dict) and stream_matches_indices(package, dataset, indices):
            matching_fields.update(cast("dict[str, Any]", dataset_fields))
    return matching_fields

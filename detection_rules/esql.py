# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""ES|QL query helpers and EventDataset extraction."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Any, cast

import esql  # type: ignore[reportMissingTypeStubs]

from . import ecs
from .config import CUSTOM_RULES_DIR

DATASET_PACKAGE_ALIASES = {
    "googlecloud": "gcp",
}
_INDEX_PACKAGE_RE = re.compile(r"^(?:logs|metrics|traces)-([a-zA-Z0-9_]+)", re.IGNORECASE)


@dataclass
class EventDataset:
    """Dataclass for event.dataset with integration and datastream parts."""

    package: str
    integration: str

    def __post_init__(self) -> None:
        self.package = normalize_dataset_package(self.package)

    def __str__(self) -> str:
        return f"{self.package}.{self.integration}"


def normalize_dataset_package(package: str) -> str:
    """Map alternate dataset package names to Fleet package names."""
    return DATASET_PACKAGE_ALIASES.get(package, package)


def get_esql_query_event_dataset_integrations(query: str, tree: Any | None = None) -> list[EventDataset]:
    """Extract event.dataset and data_stream.dataset integrations from an ES|QL query."""
    parsed: Any = tree if tree is not None else esql.parse_query(query)  # type: ignore[reportUnknownMemberType]
    seen: set[tuple[str, str]] = set()
    event_datasets: list[EventDataset] = []
    datasets: list[Any] = esql.get_event_datasets(parsed)  # type: ignore[reportUnknownMemberType]
    for dataset in datasets:
        item = EventDataset(package=dataset.package, integration=dataset.integration)
        key = (item.package, item.integration)
        if key not in seen:
            seen.add(key)
            event_datasets.append(item)
    return event_datasets


def index_patterns_match(left: str, right: str) -> bool:
    """Return whether two index patterns can match the same index name."""
    return left == right or fnmatch.fnmatch(left, right) or fnmatch.fnmatch(right, left)


def infer_packages_from_indices(indices: list[str]) -> list[str]:
    """Infer Fleet package names from explicit ES|QL FROM patterns."""
    packages: list[str] = []
    for index in indices:
        cleaned = index.replace("::", ":").split(":")[-1].strip()
        match = _INDEX_PACKAGE_RE.match(cleaned)
        if not match:
            continue
        package = normalize_dataset_package(match.group(1).lower())
        if package not in packages:
            packages.append(package)
    return packages


def collect_index_field_schemas(indices: list[str]) -> dict[str, Any]:
    """Collect non-ECS, custom, and Endpoint fields matching FROM sources."""
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
    """Return whether a Fleet package stream can back a FROM source."""
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
    """Collect only package stream fields that match the query's FROM sources."""
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

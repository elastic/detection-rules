# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""ES|QL query helpers and EventDataset extraction."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Any

import esql

from . import ecs
from .config import CUSTOM_RULES_DIR

# Legacy / alternate dataset package prefixes → Fleet package names.
DATASET_PACKAGE_ALIASES: dict[str, str] = {
    "googlecloud": "gcp",
}

# logs-<package>.… / metrics-<package>.… / traces-<package>.…
_INDEX_PACKAGE_RE = re.compile(r"^(?:logs|metrics|traces)-([a-zA-Z0-9_]+)", re.IGNORECASE)


@dataclass
class EventDataset:
    """Dataclass for event.dataset with integration and datastream parts."""

    package: str
    integration: str

    def __post_init__(self) -> None:
        self.package = DATASET_PACKAGE_ALIASES.get(self.package, self.package)

    def __str__(self) -> str:
        return f"{self.package}.{self.integration}"


def normalize_dataset_package(package: str) -> str:
    """Map alternate dataset package names to Fleet package names."""
    return DATASET_PACKAGE_ALIASES.get(package, package)


def get_esql_query_event_dataset_integrations(query: str, tree: Any | None = None) -> list[EventDataset]:
    """Extract event.dataset / data_stream.dataset integrations from an ES|QL query."""
    parsed = tree if tree is not None else esql.parse_query(query)
    seen: set[tuple[str, str]] = set()
    event_datasets: list[EventDataset] = []
    for ds in esql.get_event_datasets(parsed):
        item = EventDataset(package=ds.package, integration=ds.integration)
        key = (item.package, item.integration)
        if key not in seen:
            seen.add(key)
            event_datasets.append(item)
    return event_datasets


def index_patterns_match(left: str, right: str) -> bool:
    """Return True when two index patterns refer to overlapping names."""
    if left == right:
        return True
    return bool(fnmatch.fnmatch(left, right) or fnmatch.fnmatch(right, left))


def infer_packages_from_indices(indices: list[str]) -> list[str]:
    """Infer Fleet package names from ES|QL FROM index patterns."""
    packages: list[str] = []
    seen: set[str] = set()
    for index in indices:
        cleaned = index.replace("::", ":").split(":")[-1].strip()
        match = _INDEX_PACKAGE_RE.match(cleaned)
        if match:
            package = normalize_dataset_package(match.group(1).lower())
        elif cleaned.startswith("metrics-") or cleaned == "metrics-*":
            # Broad metrics-* datastreams commonly include Elastic Agent system metrics.
            package = "system"
        else:
            continue
        if package not in seen:
            seen.add(package)
            packages.append(package)
    return packages


def collect_index_field_schemas(indices: list[str]) -> dict[str, Any]:
    """Merge non-ECS / custom field schemas for the given FROM indices.

    Mirrors remote ``prepare_mappings`` so offline validation includes alert fields
    (``kibana.alert.*``), integration gaps tracked in ``non-ecs-schema.json``, and
    custom index schemas.
    """
    fields: dict[str, Any] = {}
    non_ecs = ecs.get_non_ecs_schema()
    for index in indices:
        fields.update(**ecs.flatten(ecs.get_index_schema(index)))
        for key, index_fields in non_ecs.items():
            if index_patterns_match(index, key):
                fields.update(index_fields)
        if CUSTOM_RULES_DIR:
            fields.update(**ecs.flatten(ecs.get_custom_index_schema(index)))
    fields.update(**ecs.flatten(ecs.get_endpoint_schemas()))
    return fields


def stream_matches_indices(package: str, dataset: str, indices: list[str]) -> bool:
    """Return True when a Fleet package stream could back any FROM index pattern."""
    if not indices:
        return True
    candidates = (
        f"logs-{package}.{dataset}*",
        f"logs-{package}.{dataset}-*",
        f"metrics-{package}.{dataset}*",
        f"metrics-{package}.{dataset}-*",
        f"traces-{package}.{dataset}*",
        f"traces-{package}.{dataset}-*",
        # endpoint events use logs-endpoint.events.<dataset>-*
        f"logs-{package}.events.{dataset}*",
        f"logs-{package}.events.{dataset}-*",
    )
    return any(index_patterns_match(index, candidate) for index in indices for candidate in candidates)


def collect_package_fields_for_indices(
    package_schema: dict[str, Any],
    package: str,
    indices: list[str],
    integration: str | None = None,
) -> dict[str, Any]:
    """Collect package fields, restricted to streams that match FROM indices.

    When *integration* is set, returns that stream only if it matches. When unset,
    unions matching streams. If no stream matches (should be rare), falls back to
    all streams so broad patterns are not under-validated.
    """
    if integration is not None:
        if integration not in package_schema:
            return {}
        if stream_matches_indices(package, integration, indices):
            return dict(package_schema[integration])
        return {}

    fields: dict[str, Any] = {}
    matched = False
    for dataset, dataset_fields in package_schema.items():
        if dataset == "jobs" or not isinstance(dataset_fields, dict):
            continue
        if stream_matches_indices(package, dataset, indices):
            matched = True
            fields.update(dataset_fields)
    if matched:
        return fields
    # Fallback: no stream key matched (e.g. unusual index shape) — keep prior
    # whole-package behavior rather than validating against an empty schema.
    return {
        field: value
        for dataset, dataset_fields in package_schema.items()
        if dataset != "jobs" and isinstance(dataset_fields, dict)
        for field, value in dataset_fields.items()
    }

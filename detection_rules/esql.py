# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""ES|QL query helpers and EventDataset extraction."""

from __future__ import annotations

import functools
import re
from dataclasses import dataclass
from typing import Any, cast

import esql

from . import ecs
from .config import CUSTOM_RULES_DIR
from .schemas.definitions import (
    ESQL_INDEX_PATTERN_REGEX,
)
from .utils import strip_index_expression

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


@dataclass
class EsqlSourceGroup:
    """Dataclass for the FROM clauses of a query that read the same index patterns."""

    indices: list[str]
    spans: list[tuple[int, int]]


def _parse_for_extraction(query: str) -> Any:
    """Parse under the current package config when the caller did not pass an AST.

    No schema is installed, so this only applies grammar, feature, and nested
    KQL/EQL hooks. Column checks stay with the validation plan.
    """
    from .config import load_current_package_version
    from .rule import set_esql_config

    cfg = set_esql_config(load_current_package_version())
    with cfg:
        return esql.parse_query(query)


def get_esql_query_event_dataset_integrations(query: str, tree: Any | None = None) -> list[EventDataset]:
    """Extract event.dataset / data_stream.dataset integrations from an ES|QL query."""
    parsed = tree if tree is not None else _parse_for_extraction(query)
    seen: set[tuple[str, str]] = set()
    event_datasets: list[EventDataset] = []
    for ds in esql.get_event_datasets(parsed):
        item = EventDataset(package=ds.package, integration=ds.integration)
        key = (item.package, item.integration)
        if key not in seen:
            seen.add(key)
            event_datasets.append(item)
    return event_datasets


def local_esql_index(source: str) -> str:
    """Drop a ``cluster:`` or ``cluster::`` prefix from an index pattern."""
    cleaned = source.strip().strip("`")
    return cleaned.replace("::", ":").split(":")[-1].strip().strip("`")


def index_patterns_match(left: str, right: str) -> bool:
    """Return True when some index name can match both patterns.

    ``*`` is any sequence and ``?`` is one character. Overlapping globs such as
    ``logs-*-foo`` and ``logs-bar-*`` match.
    """
    if left == right:
        return True
    return _index_patterns_overlap(left, right)


@functools.cache
def _index_patterns_overlap(left: str, right: str) -> bool:
    """Return True when the languages of two ``*`` / ``?`` patterns intersect."""

    @functools.cache
    def overlap(i: int, j: int) -> bool:
        if i == len(left) and j == len(right):
            return True
        if i < len(left) and left[i] == "*":
            return overlap(i + 1, j) or (j < len(right) and overlap(i, j + 1))
        if j < len(right) and right[j] == "*":
            return overlap(i, j + 1) or (i < len(left) and overlap(i + 1, j))
        if i == len(left) or j == len(right):
            return False
        if left[i] == "?" or right[j] == "?" or left[i] == right[j]:
            return overlap(i + 1, j + 1)
        return False

    return overlap(0, 0)


def _matching_non_ecs_fields(index: str, non_ecs: dict[str, Any]) -> dict[str, Any]:
    """Flatten non-ECS rows whose index pattern overlaps ``index``."""
    matched: dict[str, Any] = {}
    for key, index_fields in non_ecs.items():
        if isinstance(index_fields, dict) and index_patterns_match(index, key):
            matched.update(ecs.flatten(cast("dict[str, Any]", index_fields)))
    return matched


def infer_packages_from_indices(indices: list[str]) -> list[str]:
    """Infer Fleet package names from ES|QL FROM index patterns."""
    packages: list[str] = []
    seen: set[str] = set()
    for index in indices:
        cleaned = local_esql_index(index)
        match = _INDEX_PACKAGE_RE.match(cleaned)
        if match:
            package = normalize_dataset_package(match.group(1).lower())
        elif cleaned.startswith("metrics-"):
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

    Mirrors remote `prepare_mappings` so offline validation includes alert fields
    (`kibana.alert.*`), integration gaps tracked in `non-ecs-schema.json`, and
    custom index schemas.
    """
    fields: dict[str, Any] = {}
    non_ecs = ecs.get_non_ecs_schema()
    for index in indices:
        fields.update(**ecs.flatten(ecs.get_index_schema(index)))
        fields.update(_matching_non_ecs_fields(index, non_ecs))
        if CUSTOM_RULES_DIR:
            fields.update(**ecs.flatten(ecs.get_custom_index_schema(index)))
    fields.update(**ecs.flatten(ecs.get_endpoint_schemas()))
    return fields


def collect_lookup_index_field_schemas(indices: list[str]) -> dict[str, dict[str, Any]]:
    """Per-LOOKUP-JOIN-target field maps (no blanket endpoint union).

    Named lookup tables only receive custom / non-ECS fields that match that
    index. Fleet datastreams used as lookup targets still get their matching
    non-ECS rows here; ECS and package streams are merged by the validator.
    """
    non_ecs = ecs.get_non_ecs_schema()
    result: dict[str, dict[str, Any]] = {}
    for index in indices:
        fields: dict[str, Any] = {}
        fields.update(**ecs.flatten(ecs.get_index_schema(index)))
        fields.update(_matching_non_ecs_fields(index, non_ecs))
        if CUSTOM_RULES_DIR:
            fields.update(**ecs.flatten(ecs.get_custom_index_schema(index)))
        result[index] = fields
    return result


def lookup_index_uses_ecs(index: str) -> bool:
    """Return True when a LOOKUP JOIN target is a datastream/beat, not a named table."""
    cleaned = local_esql_index(index)
    if _INDEX_PACKAGE_RE.match(cleaned):
        return True
    return cleaned.startswith(
        ("logs-", "metrics-", "traces-", ".alerts-", "auditbeat-", "filebeat-", "winlogbeat-", "endgame-")
    )


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
    *,
    allow_fallback: bool = True,
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
        stream_fields = cast("dict[str, Any]", dataset_fields)
        if stream_matches_indices(package, dataset, indices):
            matched = True
            fields.update(stream_fields)
    if matched or not allow_fallback:
        return fields
    # Fallback: no stream key matched (e.g. unusual index shape) — keep prior
    # whole-package behavior rather than validating against an empty schema.
    fallback: dict[str, Any] = {}
    for dataset, dataset_fields in package_schema.items():
        if dataset == "jobs" or not isinstance(dataset_fields, dict):
            continue
        for field, value in cast("dict[str, Any]", dataset_fields).items():
            fallback[str(field)] = value
    return fallback


def split_esql_source_list(sources: str) -> list[str]:
    """Split a FROM clause source list into its local index patterns."""
    indices: list[str] = []
    for source in sources.split(","):
        # Truncate cross cluster search indices to local indices
        index = local_esql_index(source)
        if ESQL_INDEX_PATTERN_REGEX.match(index):
            indices.append(index)
    return indices


def get_esql_query_source_groups(query: str, tree: Any | None = None) -> list[EsqlSourceGroup]:
    """Group FROM/TS clauses by index patterns using the ES|QL AST (with rewrite spans).

    One parse yields indices for schema selection and character spans for remote
    index rewriting — no separate regex pass. Unparseable fragments return [].
    """
    try:
        parsed = tree if tree is not None else _parse_for_extraction(query)
    except Exception:  # noqa: BLE001 — incomplete fragments have no FROM groups
        return []
    return [
        EsqlSourceGroup(indices=[local_esql_index(index) for index in group.indices], spans=list(group.spans))
        for group in esql.get_from_source_groups(parsed)
    ]


def get_esql_query_indices(query: str, tree: Any | None = None) -> list[str]:
    """Extract unique FROM/TS index patterns via the ES|QL AST (CCS prefix stripped).

    Call with ``tree=`` after the offline allow_missing parse so schema planning
    reuses that AST instead of parsing again.
    """
    indices: list[str] = []
    for _, index in get_esql_query_source_patterns(query, tree=tree):
        if index not in indices:
            indices.append(index)
    return indices


def get_esql_query_source_patterns(query: str, tree: Any | None = None) -> list[tuple[str, str]]:
    """Extract unique FROM/TS sources as (pattern as written, local index pattern) pairs.

    The written form keeps any `cluster:` or `cluster::` prefix, which is what the parser
    matches when it narrows a multi-index schema to one FROM. The local pattern drops that prefix.
    """
    try:
        parsed = tree if tree is not None else _parse_for_extraction(query)
    except Exception:  # noqa: BLE001 — incomplete fragments yield no sources
        return []

    sources: list[tuple[str, str]] = []
    for source in esql.get_from_sources(parsed):
        written = source.strip()
        index = local_esql_index(written)
        if index and ESQL_INDEX_PATTERN_REGEX.match(index) and (written, index) not in sources:
            sources.append((written, index))
    return sources


def get_esql_lookup_join_targets(query: str, tree: Any | None = None) -> list[str]:
    """Extract unique LOOKUP JOIN target index names (CCS prefix stripped)."""
    try:
        parsed = tree if tree is not None else _parse_for_extraction(query)
    except Exception:  # noqa: BLE001 — incomplete fragments yield no lookup targets
        return []

    targets: list[str] = []
    for source in esql.get_lookup_join_targets(parsed):
        index = local_esql_index(source)
        if index and ESQL_INDEX_PATTERN_REGEX.match(index) and index not in targets:
            targets.append(index)
    return targets


def replace_esql_query_sources(query: str, replacements: dict[tuple[int, int], str]) -> str:
    """Replace each FROM clause source list with the index string mapped to its span."""
    # Applied back to front so that earlier spans keep their offsets
    for (start, end), replacement in sorted(replacements.items(), reverse=True):
        query = query[:start] + replacement + query[end:]
    return query

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Known ES|QL index patterns for offline FROM and LOOKUP JOIN checks."""

import re
from typing import Any

from semver import Version

from . import ecs, integrations
from .config import CUSTOM_RULES_DIR
from .esql import EventDataset, index_patterns_match
from .esql_errors import EsqlUnknownIndexError
from .integrations import (
    load_integrations_manifests,
    load_integrations_schemas,
)
from .rule import RuleMeta


def get_rule_integrations(metadata: RuleMeta) -> list[str]:
    """Return a copy of the rule's integration package names."""
    # Callers append inferred packages. A copy keeps LOOKUP JOIN targets off metadata.integration.
    if metadata.integration:
        if isinstance(metadata.integration, list):
            return list(metadata.integration)
        return [metadata.integration]
    return []


def resolve_rule_packages(
    rule_integrations: list[str],
    event_dataset_integrations: list[EventDataset],
) -> tuple[list[str], dict[str, list[str]]]:
    """Resolve packages and the streams allowed for packages named only by event.dataset."""
    from .esql import normalize_dataset_package

    # Metadata packages keep every data stream. event.dataset values are regex-extracted and may
    # sit inside OR branches, so only packages referenced solely through event.dataset are restricted.
    packages = list(dict.fromkeys(normalize_dataset_package(package) for package in rule_integrations))
    dataset_restriction: dict[str, list[str]] = {}
    for event_dataset in event_dataset_integrations:
        package = normalize_dataset_package(event_dataset.package)
        if package in packages:
            continue
        packages.append(package)
        dataset_restriction.setdefault(package, []).append(event_dataset.integration)

    return packages, dataset_restriction


def esql_indices_covered_by_packages(
    indices: list[str],
    rule_integrations: list[str],
    event_dataset_integrations: list[EventDataset],
) -> bool:
    """Return True when every FROM index resolves to one of the rule's integration packages."""
    # Beats indices (auditbeat-*, filebeat-*, ...) have their own schemas, which this check does
    # not model, so rules reading them keep the full-ECS fallback.
    if not indices:
        return False
    packages, _ = resolve_rule_packages(rule_integrations, event_dataset_integrations)
    for index in indices:
        if not index.startswith("logs-"):
            return False
        package = re.split(r"[.\-*]", index.removeprefix("logs-"), maxsplit=1)[0]
        if package not in packages:
            return False
    return True


def integration_stream_keys(
    rule_integrations: list[str],
    event_dataset_integrations: list[EventDataset],
    package_manifests: Any,
    integration_schemas: Any,
    stack_version: str,
) -> set[str]:
    """Return Fleet stream ids (package-stream) for the rule's packages."""
    rule_integrations, dataset_restriction = resolve_rule_packages(rule_integrations, event_dataset_integrations)
    keys: set[str] = set()
    for integration in rule_integrations:
        # Dataset strings are not always Fleet packages. A custom data stream named in
        # data_stream.dataset must not abort prebuilt index checks.
        if integration not in package_manifests or integration not in integration_schemas:
            continue
        try:
            package_version, _ = integrations.find_latest_compatible_version(
                integration,
                "",
                Version.parse(stack_version),
                package_manifests,
            )
        except ValueError:
            continue
        package_schema = integration_schemas[integration][package_version]
        if integration in dataset_restriction:
            allowed_keys = dataset_restriction[integration]
            streams = [key for key in package_schema if key in allowed_keys]
        else:
            streams = list(package_schema)
        keys.update(f"{integration}-{stream}" for stream in streams)
    return keys


def collect_known_esql_index_patterns(stream_keys: set[str], indices: list[str]) -> set[str]:
    """Build known ES|QL index patterns from Fleet streams plus non-ECS and custom schemas."""
    usable = {key for key in stream_keys if key not in indices}
    filtered_keys: set[str] = set()
    for prefix in ("logs-", "metrics-", "traces-"):
        filtered_keys.update(prefix + key.replace("-", ".") + "*" for key in usable)
        filtered_keys.update(prefix + key.replace("-", ".") + "-*" for key in usable)
    filtered_keys = {
        key.replace("logs-endpoint.", "logs-endpoint.events.") if key.startswith("logs-endpoint.") else key
        for key in filtered_keys
    }
    filtered_keys.update(ecs.get_non_ecs_schema().keys())
    filtered_keys.update(ecs.get_custom_schemas().keys())
    filtered_keys.add("logs-endpoint.alerts-*")
    # Packetbeat is an official index with no non-ECS schema entry. Shipped rules read it.
    filtered_keys.add("packetbeat-*")
    return filtered_keys


def assert_known_esql_indices(indices: list[str], stream_keys: set[str]) -> list[str]:
    """Return known patterns matching FROM indices."""
    filtered_keys = collect_known_esql_index_patterns(stream_keys, indices)
    matches: list[str] = []
    unmatched: list[str] = []
    for index in indices:
        index_matches = [key for key in filtered_keys if index_patterns_match(index, key)]
        if index_matches:
            matches.extend(index_matches)
        else:
            unmatched.append(index)

    if unmatched or not indices:
        unknown = unmatched or indices
        raise EsqlUnknownIndexError(
            f"Unknown index pattern(s): {', '.join(unknown)}. Known patterns: {', '.join(sorted(filtered_keys))}"
        )

    if "logs-endpoint.alerts-*" in matches and "logs-endpoint.events.alerts-*" not in matches:
        matches.append("logs-endpoint.events.alerts-*")
    return matches


_OFFLINE_STREAM_KEY_CACHE: dict[tuple[Any, ...], set[str]] = {}


def validate_offline_esql_from_indices(
    indices: list[str],
    metadata: RuleMeta,
    event_dataset_integrations: list[EventDataset],
    stack_version: str,
) -> list[str]:
    """Reject unknown FROM and LOOKUP JOIN patterns on prebuilt rules."""
    # Custom-rules directories hold custom rules and customized prebuilt rules.
    # Their data streams are not in the Fleet manifests, so this check does not apply.
    if CUSTOM_RULES_DIR:
        return list(indices)

    from .esql import infer_packages_from_indices

    rule_integrations = get_rule_integrations(metadata)
    for package in infer_packages_from_indices(indices):
        if package not in rule_integrations:
            rule_integrations.append(package)

    package_manifests = load_integrations_manifests()
    integration_schemas = load_integrations_schemas()
    known_packages = [p for p in rule_integrations if p in integration_schemas and p in package_manifests]
    datasets_key = tuple(sorted((ds.package, ds.integration) for ds in event_dataset_integrations))
    cache_key = (tuple(sorted(known_packages)), datasets_key, str(stack_version))
    stream_keys: set[str] | None = _OFFLINE_STREAM_KEY_CACHE.get(cache_key)
    if stream_keys is None:
        stream_keys = set[str]()
        if known_packages:
            stream_keys = integration_stream_keys(
                known_packages,
                event_dataset_integrations,
                package_manifests,
                integration_schemas,
                stack_version,
            )
        _OFFLINE_STREAM_KEY_CACHE[cache_key] = stream_keys

    return assert_known_esql_indices(indices, stream_keys)

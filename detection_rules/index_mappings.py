# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Validation logic for rules containing queries."""

import re
from collections.abc import Callable
from copy import deepcopy
from typing import Any, cast

from semver import Version

from . import ecs, integrations, utils
from .esql import EventDataset
from .esql_errors import EsqlUnknownIndexError
from .integrations import (
    load_integrations_manifests,
    load_integrations_schemas,
)
from .rule import RuleMeta


def delete_nested_key_from_dict(d: dict[str, Any], compound_key: str) -> None:
    """Delete a nested key from a dictionary."""
    keys = compound_key.split(".")
    for key in keys[:-1]:
        if key in d and isinstance(d[key], dict):
            d = d[key]  # type: ignore[reportUnknownVariableType]
        else:
            return
    d.pop(keys[-1], None)


def flat_schema_to_index_mapping(flat_schema: dict[str, str]) -> dict[str, Any]:
    """
    Convert dicts with flat JSON paths and values into a nested mapping with
    intermediary `properties`, `fields` and `type` fields.
    """

    # Sorting here ensures that 'a.b' processed before 'a.b.c', allowing us to correctly
    # detect and handle multi-fields.
    sorted_items = sorted(flat_schema.items())
    result = {}

    for field_path, field_type in sorted_items:
        parts = field_path.split(".")
        current_level = result

        for part in parts[:-1]:
            node = current_level.setdefault(part, {})  # type: ignore[reportUnknownVariableType]

            if "type" in node and node["type"] not in ("nested", "object"):
                current_level = node.setdefault("fields", {})  # type: ignore[reportUnknownVariableType]
            else:
                current_level = node.setdefault("properties", {})  # type: ignore[reportUnknownVariableType]

        leaf_key = parts[-1]
        current_level[leaf_key] = {"type": field_type}

        # add `scaling_factor` field missing in the schema
        # https://www.elastic.co/docs/reference/elasticsearch/mapping-reference/number#scaled-float-params
        if field_type == "scaled_float":
            current_level[leaf_key]["scaling_factor"] = 1000

        # add `path` field for `alias` fields, set to a dummy value
        if field_type == "alias":
            current_level[leaf_key]["path"] = "@timestamp"

    return result  # type: ignore[reportUnknownVariableType]


def get_rule_integrations(metadata: RuleMeta) -> list[str]:
    """Retrieve rule integrations from metadata.

    Always return a shallow copy so callers can append inferred packages without
    mutating ``metadata.integration`` (LOOKUP JOIN targets must not become FROM packages).
    """
    if metadata.integration:
        if isinstance(metadata.integration, list):
            return list(metadata.integration)
        return [metadata.integration]
    return []


_SCALAR_MAPPING_TYPES = frozenset(
    {
        "keyword",
        "text",
        "match_only_text",
        "wildcard",
        "constant_keyword",
        "long",
        "integer",
        "short",
        "byte",
        "double",
        "float",
        "half_float",
        "scaled_float",
        "boolean",
        "date",
        "date_nanos",
        "ip",
        "version",
        "binary",
        "geo_point",
        "geo_shape",
        "flattened",
    }
)


def combine_index_mappings(dest: dict[str, Any], src: dict[str, Any]) -> None:
    """Merge nested index mappings without creating invalid scalar+properties shapes."""
    for key, value in src.items():
        existing = dest.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            value_map = cast("dict[str, Any]", value)
            existing_map = cast("dict[str, Any]", existing)
            raw_src_type = value_map.get("type")
            raw_dest_type = existing_map.get("type")
            src_type = raw_src_type if isinstance(raw_src_type, str) else None
            dest_type = raw_dest_type if isinstance(raw_dest_type, str) else None
            src_has_props = isinstance(value_map.get("properties"), dict)
            dest_has_props = isinstance(existing_map.get("properties"), dict)

            # Prefer object shapes over scalars (e.g. ECS keyword vs integration object).
            if src_has_props and not dest_has_props:
                dest[key] = value_map
            elif dest_has_props and not src_has_props and src_type in _SCALAR_MAPPING_TYPES:
                # Keep the richer object mapping already present.
                continue
            elif (src_type in _SCALAR_MAPPING_TYPES and not src_has_props) or (
                dest_type in _SCALAR_MAPPING_TYPES and src_has_props
            ):
                dest[key] = value_map
            else:
                combine_index_mappings(existing_map, value_map)
        else:
            dest[key] = value


def prune_scalar_fields_with_subfields(mapping: dict[str, Any]) -> dict[str, Any]:
    """Drop `properties`/`fields` under scalar types (invalid ES mappings)."""
    for value in mapping.values():
        if not isinstance(value, dict):
            continue
        value_map = cast("dict[str, Any]", value)
        field_type = value_map.get("type")
        if isinstance(field_type, str) and field_type in _SCALAR_MAPPING_TYPES:
            value_map.pop("properties", None)
            # Keep multi-fields on scalars; only drop nested object properties above.
        nested = value_map.get("properties")
        if isinstance(nested, dict):
            _ = prune_scalar_fields_with_subfields(cast("dict[str, Any]", nested))
        fields = value_map.get("fields")
        if isinstance(fields, dict):
            _ = prune_scalar_fields_with_subfields(cast("dict[str, Any]", fields))
    return mapping


def prune_mappings_of_unsupported_types(
    debug_str_data_source: str, stream_mappings: dict[str, Any], log: Callable[[str], None]
) -> dict[str, Any]:
    """Prune fields with unsupported types (ES|QL) from the provided mappings."""
    nested_multifields = find_nested_multifields(stream_mappings)
    for field in nested_multifields:
        parts = str(field).split(".fields.")[0].split(".")
        base_name = ".properties.".join(parts)
        field_name = f"{base_name}.fields"
        log(
            f"Warning: Nested multi-field `{field}` found in `{debug_str_data_source}`. "
            f"Removing parent field from schema for ES|QL validation."
        )
        delete_nested_key_from_dict(stream_mappings, field_name)
    nested_flattened_fields = find_flattened_fields_with_subfields(stream_mappings)
    for field in nested_flattened_fields:
        # Remove both .fields and .properties entries for flattened fields
        # .properties entries can occur when being merged with non-ecs or custom schemas
        parts = str(field).split(".fields.")[0].split(".")
        base_name = ".properties.".join(parts)
        field_name = f"{base_name}.fields"
        property_name = f"{base_name}.properties"
        log(
            f"Warning: flattened field `{field}` found in `{debug_str_data_source}` with sub fields. "
            f"Removing parent field from schema for ES|QL validation."
        )
        delete_nested_key_from_dict(stream_mappings, field_name)
        delete_nested_key_from_dict(stream_mappings, property_name)
    return stream_mappings


def resolve_rule_packages(
    rule_integrations: list[str],
    event_dataset_integrations: list[EventDataset],
) -> tuple[list[str], dict[str, list[str]]]:
    """Resolve a rule's packages and the data stream restrictions for packages named only by event.dataset."""
    from .esql import normalize_dataset_package

    # Metadata packages keep every data stream: event.dataset values are regex-extracted and may sit
    # inside OR branches, so they cannot be trusted to drop fields. Only packages referenced solely
    # through event.dataset are restricted to the named streams.
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
    # Beats indices (auditbeat-*, filebeat-*, ...) have their own schemas, which the ES|QL mapping
    # build does not model, so rules reading them keep the full-ECS fallback.
    if not indices:
        # nothing extracted from FROM: do not pass vacuously
        return False
    packages, _ = resolve_rule_packages(rule_integrations, event_dataset_integrations)
    for index in indices:
        if not index.startswith("logs-"):
            return False
        package = re.split(r"[.\-*]", index.removeprefix("logs-"), maxsplit=1)[0]
        if package not in packages:
            return False
    return True


def prepare_integration_mappings(  # noqa: PLR0913, PLR0917
    rule_integrations: list[str],
    event_dataset_integrations: list[EventDataset],
    package_manifests: Any,
    integration_schemas: Any,
    stack_version: str,
    log: Callable[[str], None],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Prepare integration mappings for the given rule integrations."""
    integration_mappings: dict[str, Any] = {}
    index_lookup: dict[str, Any] = {}

    rule_integrations, dataset_restriction = resolve_rule_packages(rule_integrations, event_dataset_integrations)

    for integration in rule_integrations:
        package = integration
        package_version, _ = integrations.find_latest_compatible_version(
            package,
            "",
            Version.parse(stack_version),
            package_manifests,
        )
        package_schema = integration_schemas[package][package_version]

        # Apply dataset restrictions if any
        if integration in dataset_restriction:
            allowed_keys = dataset_restriction[integration]
            package_schema = {key: value for key, value in package_schema.items() if key in allowed_keys}

        for stream in package_schema:
            flat_schema = package_schema[stream]
            stream_mappings = flat_schema_to_index_mapping(flat_schema)
            stream_mappings = prune_mappings_of_unsupported_types(f"{integration}-{stream}", stream_mappings, log)
            utils.combine_dicts(integration_mappings, deepcopy(stream_mappings))
            index_lookup[f"{integration}-{stream}"] = stream_mappings

    return integration_mappings, index_lookup


def collect_known_esql_index_patterns(index_lookup: dict[str, Any], indices: list[str]) -> set[str]:
    """Build the set of known ES|QL index patterns from Fleet streams + non-ECS/custom."""
    # Assumes valid index format is logs-<integration>.<package>* or logs-<integration>.<package>-*
    filtered_keys = {"logs-" + key.replace("-", ".") + "*" for key in index_lookup if key not in indices}
    filtered_keys.update({"logs-" + key.replace("-", ".") + "-*" for key in index_lookup if key not in indices})
    # Replace "logs-endpoint." with "logs-endpoint.events."
    filtered_keys = {
        key.replace("logs-endpoint.", "logs-endpoint.events.") if "logs-endpoint." in key else key
        for key in filtered_keys
    }
    filtered_keys.update(ecs.get_non_ecs_schema().keys())
    filtered_keys.update(ecs.get_custom_schemas().keys())
    filtered_keys.add("logs-endpoint.alerts-*")
    return filtered_keys


def assert_known_esql_indices(indices: list[str], index_lookup: dict[str, Any]) -> list[str]:
    """Return known patterns matching FROM indices; raise if none match."""
    filtered_keys = collect_known_esql_index_patterns(index_lookup, indices)
    matches: list[str] = []
    for index in indices:
        pattern = re.compile(re.escape(index.rstrip("-")).replace(r"\*", ".*"))
        matches.extend([key for key in filtered_keys if pattern.fullmatch(key)])

    if not matches:
        raise EsqlUnknownIndexError(
            f"Unknown index pattern(s): {', '.join(indices)}. Known patterns: {', '.join(sorted(filtered_keys))}"
        )

    if "logs-endpoint.alerts-*" in matches and "logs-endpoint.events.alerts-*" not in matches:
        matches.append("logs-endpoint.events.alerts-*")
    return matches


_OFFLINE_INDEX_LOOKUP_CACHE: dict[tuple[Any, ...], dict[str, Any]] = {}


def validate_offline_esql_from_indices(
    indices: list[str],
    metadata: RuleMeta,
    event_dataset_integrations: list[EventDataset],
    stack_version: str,
) -> list[str]:
    """Reject FROM and LOOKUP JOIN patterns that match no known index."""
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
    index_lookup = _OFFLINE_INDEX_LOOKUP_CACHE.get(cache_key)
    if index_lookup is None:
        index_lookup = {}
        if known_packages:
            _, index_lookup = prepare_integration_mappings(
                known_packages,
                event_dataset_integrations,
                package_manifests,
                integration_schemas,
                stack_version,
                lambda _msg: None,
            )
        _OFFLINE_INDEX_LOOKUP_CACHE[cache_key] = index_lookup

    return assert_known_esql_indices(indices, index_lookup)


def find_nested_multifields(mapping: dict[str, Any], path: str = "") -> list[Any]:
    """Recursively search for nested multi-fields in Elasticsearch mappings."""
    nested_multifields = []

    for field, properties in mapping.items():
        current_path = f"{path}.{field}" if path else field

        if isinstance(properties, dict):
            # Check if the field has a `fields` key
            if "fields" in properties:
                # Check if any subfield in `fields` also has a `fields` key
                for subfield, subproperties in properties["fields"].items():  # type: ignore[reportUnknownVariableType]
                    if isinstance(subproperties, dict) and "fields" in subproperties:
                        nested_multifields.append(f"{current_path}.fields.{subfield}")  # type: ignore[reportUnknownVariableType]

            # Recurse into subfields
            if "properties" in properties:
                nested_multifields.extend(  # type: ignore[reportUnknownVariableType]
                    find_nested_multifields(properties["properties"], current_path)  # type: ignore[reportUnknownVariableType]
                )

    return nested_multifields  # type: ignore[reportUnknownVariableType]


def find_flattened_fields_with_subfields(mapping: dict[str, Any], path: str = "") -> list[str]:
    """Recursively search for type 'flattened' that have a 'fields' or 'properties' key in Elasticsearch mappings."""
    flattened_fields_with_subfields: list[str] = []

    for field, properties in mapping.items():
        current_path = f"{path}.{field}" if path else field

        if isinstance(properties, dict):
            # Check if the field is of type 'flattened' and has a 'fields' key
            if properties.get("type") == "flattened" and "fields" in properties:  # type: ignore[reportUnknownVariableType]
                flattened_fields_with_subfields.append(current_path)  # type: ignore[reportUnknownVariableType]
            # Check if the field is of type 'flattened' and has a 'properties' key
            if properties.get("type") == "flattened" and "properties" in properties:  # type: ignore[reportUnknownVariableType]
                flattened_fields_with_subfields.append(current_path)  # type: ignore[reportUnknownVariableType]

            # Recurse into subfields
            if "properties" in properties:
                flattened_fields_with_subfields.extend(  # type: ignore[reportUnknownVariableType]
                    find_flattened_fields_with_subfields(properties["properties"], current_path)  # type: ignore[reportUnknownVariableType]
                )

    return flattened_fields_with_subfields

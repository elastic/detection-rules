# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Validation logic for rules containing queries."""

import re
from collections.abc import Callable
from copy import deepcopy
from typing import Any

from elasticsearch import Elasticsearch  # type: ignore[reportMissingTypeStubs]
from semver import Version

from . import ecs, integrations, utils
from .config import load_current_package_version
from .esql import EventDataset
from .esql_errors import (
    EsqlKibanaBaseError,
    EsqlSchemaError,
    EsqlSyntaxError,
    EsqlTypeMismatchError,
    EsqlUnknownIndexError,
    EsqlUnsupportedTypeError,
)
from .esql_parser import EsqlValidator, get_shared_validator
from .integrations import (
    load_integrations_manifests,
    load_integrations_schemas,
)
from .rule import RuleMeta
from .schemas import get_stack_schemas
from .utils import combine_dicts


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
    """Retrieve rule integrations from metadata."""
    if metadata.integration:
        rule_integrations: list[str] = (
            metadata.integration if isinstance(metadata.integration, list) else [metadata.integration]
        )
    else:
        rule_integrations: list[str] = []
    return rule_integrations


def get_existing_mappings(
    elastic_client: Elasticsearch | None, indices: list[str]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Retrieve mappings for all matching existing index templates."""
    # When elastic_client is None we skip simulate_index_template entirely; callers
    # fall back to local integration / ECS / custom schemas.
    existing_mappings: dict[str, Any] = {}
    index_lookup: dict[str, Any] = {}
    if elastic_client is None:
        return existing_mappings, index_lookup
    for index in indices:
        index_tmpl_mappings = get_simulated_index_template_mappings(elastic_client, index)
        index_lookup[index] = index_tmpl_mappings
        combine_dicts(existing_mappings, index_tmpl_mappings)
    return existing_mappings, index_lookup


def get_simulated_index_template_mappings(elastic_client: Elasticsearch, name: str) -> dict[str, Any]:
    """
    Return the mappings from the index configuration that would be applied
    to the specified index from an existing index template

    https://elasticsearch-py.readthedocs.io/en/stable/api/indices.html#elasticsearch.client.IndicesClient.simulate_index_template
    """
    template = elastic_client.indices.simulate_index_template(name=name)
    if not template:
        return {}
    return template["template"]["mappings"]["properties"]


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


def prepare_integration_mappings(  # noqa: PLR0913
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
    dataset_restriction: dict[str, list[str]] = {}

    # Process restrictions, note we need this for loops to be separate
    for event_dataset in event_dataset_integrations:
        # Ensure the integration is in rule_integrations
        if event_dataset.package not in rule_integrations:
            dataset_restriction.setdefault(event_dataset.package, []).append(event_dataset.integration)
    for event_dataset in event_dataset_integrations:
        if event_dataset.package not in rule_integrations:
            rule_integrations.append(event_dataset.package)

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


def get_index_to_package_lookup(indices: list[str], index_lookup: dict[str, Any]) -> dict[str, Any]:
    """Get a lookup of index patterns to package names for the provided indices."""
    index_lookup_indices: dict[str, Any] = {}
    for key in index_lookup:
        if key not in indices:
            # Add logs-<key>* and logs-<key>-*
            transformed_key_star = f"logs-{key.replace('-', '.')}*"
            transformed_key_dash = f"logs-{key.replace('-', '.')}-*"
            if "logs-endpoint." in transformed_key_star or "logs-endpoint." in transformed_key_dash:
                transformed_key_star = transformed_key_star.replace("logs-endpoint.", "logs-endpoint.events.")
                transformed_key_dash = transformed_key_dash.replace("logs-endpoint.", "logs-endpoint.events.")
            index_lookup_indices[transformed_key_star] = key.replace("-", ".")
            index_lookup_indices[transformed_key_dash] = key.replace("-", ".")

    return index_lookup_indices


def get_filtered_index_schema(  # noqa: PLR0913
    indices: list[str],
    index_lookup: dict[str, Any],
    ecs_schema: dict[str, Any],
    non_ecs_mapping: dict[str, Any],
    custom_mapping: dict[str, Any],
    log: Callable[[str], None],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Check if the provided indices are known based on the integration format. Returns the combined schema."""

    non_ecs_indices = ecs.get_non_ecs_schema()
    custom_indices = ecs.get_custom_schemas()

    # Assumes valid index format is logs-<integration>.<package>* or logs-<integration>.<package>-*
    filtered_keys = {"logs-" + key.replace("-", ".") + "*" for key in index_lookup if key not in indices}
    filtered_keys.update({"logs-" + key.replace("-", ".") + "-*" for key in index_lookup if key not in indices})
    # Replace "logs-endpoint." with "logs-endpoint.events."
    filtered_keys = {
        key.replace("logs-endpoint.", "logs-endpoint.events.") if "logs-endpoint." in key else key
        for key in filtered_keys
    }
    filtered_keys.update(non_ecs_indices.keys())
    filtered_keys.update(custom_indices.keys())
    filtered_keys.add("logs-endpoint.alerts-*")

    matches: list[str] = []
    for index in indices:
        pattern = re.compile(index.replace(".", r"\.").replace("*", ".*").rstrip("-"))
        matches.extend([key for key in filtered_keys if pattern.fullmatch(key)])

    if not matches:
        raise EsqlUnknownIndexError(
            f"Unknown index pattern(s): {', '.join(indices)}. Known patterns: {', '.join(filtered_keys)}"
        )

    if "logs-endpoint.alerts-*" in matches and "logs-endpoint.events.alerts-*" not in matches:
        matches.append("logs-endpoint.events.alerts-*")

    # Now that we have the matched indices, we need to filter the index lookup to only include those indices
    filtered_index_lookup = {
        "logs-" + key.replace("-", ".") + "*": value for key, value in index_lookup.items() if key not in indices
    }
    filtered_index_lookup.update(
        {"logs-" + key.replace("-", ".") + "-*": value for key, value in index_lookup.items() if key not in indices}
    )
    filtered_index_lookup = {
        key.replace("logs-endpoint.", "logs-endpoint.events."): value for key, value in filtered_index_lookup.items()
    }

    # Reduce the combined mappings to only the matched indices (local schema validation source of truth)
    # Custom and non-ecs mappings are filtered before being sent to this function in prepare mappings
    combined_mappings: dict[str, Any] = {}
    utils.combine_dicts(combined_mappings, deepcopy(ecs_schema))
    for match in matches:
        base = filtered_index_lookup.get(match, {})
        # Update filtered index with non-ecs and custom mappings
        # Need to use a merge here to not overwrite existing fields
        utils.combine_dicts(base, deepcopy(non_ecs_mapping.get(match, {})))
        utils.combine_dicts(base, deepcopy(custom_mapping.get(match, {})))
        filtered_index_lookup[match] = prune_mappings_of_unsupported_types(match, base, log)
        utils.combine_dicts(combined_mappings, deepcopy(base))

    # Reduce the index lookup to only the matched indices (remote/Kibana schema validation source of truth)
    filtered_index_mapping: dict[str, Any] = {}
    index_lookup_indices = get_index_to_package_lookup(indices, index_lookup)
    for match in matches:
        if match in index_lookup_indices:
            index_name = index_lookup_indices[match].replace(".", "-")
            filtered_index_mapping[index_name] = index_lookup[index_name]
        else:
            filtered_index_mapping[match] = filtered_index_lookup.get(match, {})

    return combined_mappings, filtered_index_mapping


def execute_query_against_indices(
    elastic_client: Elasticsearch | None,
    query: str,
    indices: dict[str, dict[str, Any]],
    log: Callable[[str], None],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Validate an ES|QL query locally via the embedded Java validator."""
    # indices: {pattern: {"properties": {...}}} for each FROM target. elastic_client
    # is only forwarded to error classes for opportunistic cleanup of stale
    # rule-test-* indices from older remote runs; no query is sent to the cluster.
    # Returns (columns, response) — columns matches the ES|QL HTTP API shape; response
    # is a dict with a top-level "columns" key so callers expecting that wrapper work.
    log(f"Validating ES|QL query locally against {len(indices)} index pattern(s)")

    shared = get_shared_validator()
    if shared is not None:
        result = shared.validate(query, indices=indices)
    else:
        with EsqlValidator() as v:
            result = v.validate(query, indices=indices)

    if result.ok:
        log(f"Got query columns: {', '.join(c.get('name', '') for c in result.columns)}")
        return result.columns, {"columns": result.columns}

    # Map validator diagnostics back to the same exception types the remote path
    # raised, so existing callers (and error-classification logic upstream) work
    # unchanged.
    first = result.errors[0] if result.errors else None
    err_msg = first.message if first else f"status={result.status}"
    if result.status == "parse_error":
        raise EsqlSyntaxError(err_msg, elastic_client) from None
    if result.status == "verify_error":
        # Verifier messages are stable enough to substring-match. Unknown-column
        # phrasing varies slightly (e.g. "Unknown column [x]" vs "unknown column").
        lower = err_msg.lower()
        if "unknown column" in lower or "unknown function" in lower:
            raise EsqlSchemaError(err_msg, elastic_client) from None
        if "unsupported type" in lower:
            raise EsqlUnsupportedTypeError(err_msg, elastic_client) from None
        raise EsqlTypeMismatchError(err_msg, elastic_client) from None
    raise EsqlKibanaBaseError(err_msg, elastic_client) from None


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


def get_ecs_schema_mappings(current_version: Version) -> dict[str, Any]:
    """Get the ECS schema in an index mapping format (nested schema) handling scaled floats."""
    ecs_version = get_stack_schemas()[str(current_version)]["ecs"]
    ecs_schemas = ecs.get_schemas()
    ecs_schema_flattened: dict[str, Any] = {}
    ecs_schema_scaled_floats: dict[str, Any] = {}
    for index, info in ecs_schemas[ecs_version]["ecs_flat"].items():
        if info["type"] == "scaled_float":
            ecs_schema_scaled_floats.update({index: info["scaling_factor"]})
        ecs_schema_flattened.update({index: info["type"]})
    ecs_schema = utils.convert_to_nested_schema(ecs_schema_flattened)
    for index, info in ecs_schema_scaled_floats.items():
        parts = index.split(".")
        current = ecs_schema

        # Traverse the ecs_schema to the correct nested dictionary
        for part in parts[:-1]:  # Traverse all parts except the last one
            current = current.setdefault(part, {}).setdefault("properties", {})

        current[parts[-1]].update({"scaling_factor": info})
    return ecs_schema


def prepare_mappings(  # noqa: PLR0913
    elastic_client: Elasticsearch | None,
    indices: list[str],
    event_dataset_integrations: list[EventDataset],
    metadata: RuleMeta,
    stack_version: str,
    log: Callable[[str], None],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Prepare index mappings for the given indices and rule integrations."""
    # When elastic_client is None, get_existing_mappings returns empty and we rely
    # solely on local integration, ECS, non-ECS and custom schemas below.
    existing_mappings, index_lookup = get_existing_mappings(elastic_client, indices)

    # Collect mappings for the integrations
    rule_integrations = get_rule_integrations(metadata)

    # Collect mappings for all relevant integrations for the given stack version
    package_manifests = load_integrations_manifests()
    integration_schemas = load_integrations_schemas()

    integration_mappings, integration_index_lookup = prepare_integration_mappings(
        rule_integrations, event_dataset_integrations, package_manifests, integration_schemas, stack_version, log
    )

    index_lookup.update(integration_index_lookup)

    # Load non-ecs schema and convert to index mapping format (nested schema)
    # For non_ecs we need both a mapping and a schema as custom schemas can override non-ecs fields
    # In these cases we need to accept the overwrite keep the original non-ecs field in the schema
    non_ecs_schema: dict[str, Any] = {}
    non_ecs_mapping: dict[str, Any] = {}
    non_ecs = ecs.get_non_ecs_schema()
    for index in indices:
        index_mapping = non_ecs.get(index, {})
        non_ecs_schema.update(index_mapping)
        index_mapping = ecs.flatten(index_mapping)
        index_mapping = utils.convert_to_nested_schema(index_mapping)
        non_ecs_mapping.update({index: index_mapping})

    # These need to be handled separately as we need to be able to validate non-ecs fields as a whole
    # and also at a per index level as custom schemas can override non-ecs fields and/or indices
    non_ecs_schema = ecs.flatten(non_ecs_schema)
    non_ecs_schema = utils.convert_to_nested_schema(non_ecs_schema)
    non_ecs_schema = prune_mappings_of_unsupported_types("non-ecs", non_ecs_schema, log)

    # Load custom schema and convert to index mapping format (nested schema)
    custom_mapping: dict[str, Any] = {}
    custom_indices = ecs.get_custom_schemas()
    for index in indices:
        index_mapping = custom_indices.get(index, {})
        index_mapping = ecs.flatten(index_mapping)
        index_mapping = utils.convert_to_nested_schema(index_mapping)
        custom_mapping.update({index: index_mapping})

    # Load ECS in an index mapping format (nested schema)
    current_version = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
    ecs_schema = get_ecs_schema_mappings(current_version)

    # Filter combined mappings based on the provided indices
    combined_mappings, index_lookup = get_filtered_index_schema(
        indices, index_lookup, ecs_schema, non_ecs_mapping, custom_mapping, log
    )

    index_lookup.update({"rule-ecs-index": ecs_schema})

    if (not integration_mappings or existing_mappings) and not non_ecs_schema and not ecs_schema:
        raise ValueError("No mappings found")
    index_lookup.update({"rule-non-ecs-index": non_ecs_schema})
    utils.combine_dicts(combined_mappings, deepcopy(non_ecs_schema))

    return existing_mappings, index_lookup, combined_mappings

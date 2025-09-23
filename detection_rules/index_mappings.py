# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Validation logic for rules containing queries."""

import time
from collections.abc import Callable
from typing import Any

from elastic_transport import ObjectApiResponse
from elasticsearch import Elasticsearch  # type: ignore[reportMissingTypeStubs]
from elasticsearch.exceptions import BadRequestError
from semver import Version

from . import ecs, integrations, misc, utils
from .config import load_current_package_version
from .esql_errors import EsqlSchemaError, EsqlSemanticError, EsqlSyntaxError, cleanup_empty_indices
from .integrations import (
    load_integrations_manifests,
    load_integrations_schemas,
)
from .rule import RuleMeta
from .schemas import get_stack_schemas
from .schemas.definitions import HTTP_STATUS_BAD_REQUEST
from .utils import combine_dicts


def get_rule_integrations(metadata: RuleMeta) -> list[str]:
    """Retrieve rule integrations from metadata."""
    if metadata.integration:
        rule_integrations: list[str] = (
            metadata.integration if isinstance(metadata.integration, list) else [metadata.integration]
        )
    else:
        rule_integrations: list[str] = []
    return rule_integrations


def create_index_with_index_mapping(
    elastic_client: Elasticsearch, index_name: str, mappings: dict[str, Any]
) -> ObjectApiResponse[Any] | None:
    """Create an index with the specified mappings and settings to support large number of fields and nested objects."""
    try:
        return elastic_client.indices.create(
            index=index_name,
            mappings={"properties": mappings},
            settings={
                "index.mapping.total_fields.limit": 10000,
                "index.mapping.nested_fields.limit": 500,
                "index.mapping.nested_objects.limit": 10000,
            },
        )
    except BadRequestError as e:
        error_message = str(e)
        if (
            e.status_code == HTTP_STATUS_BAD_REQUEST
            and "validation_exception" in error_message
            and "Validation Failed: 1: this action would add [2] shards" in error_message
        ):
            cleanup_empty_indices(elastic_client)
            try:
                return elastic_client.indices.create(
                    index=index_name,
                    mappings={"properties": mappings},
                    settings={
                        "index.mapping.total_fields.limit": 10000,
                        "index.mapping.nested_fields.limit": 500,
                        "index.mapping.nested_objects.limit": 10000,
                    },
                )
            except BadRequestError as retry_error:
                raise EsqlSchemaError(str(retry_error), elastic_client) from retry_error
        raise EsqlSchemaError(error_message, elastic_client) from e


def get_existing_mappings(elastic_client: Elasticsearch, indices: list[str]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Retrieve mappings for all matching existing index templates."""
    existing_mappings: dict[str, Any] = {}
    index_lookup: dict[str, Any] = {}
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


def prepare_integration_mappings(  # noqa: PLR0913
    rule_integrations: list[str],
    event_dataset_integrations: list[utils.EventDataset],
    package_manifests: Any,
    integration_schemas: Any,
    stack_version: str,
    log: Callable[[str], None],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Prepare integration mappings for the given rule integrations."""
    integration_mappings: dict[str, Any] = {}
    index_lookup: dict[str, Any] = {}
    dataset_restriction: dict[str, str] = {}

    # Process restrictions, note we need this for loops to be separate
    for event_dataset in event_dataset_integrations:
        # Ensure the integration is in rule_integrations
        if event_dataset.integration not in rule_integrations:
            dataset_restriction.setdefault(event_dataset.integration, []).append(event_dataset.datastream)  # type: ignore[reportIncompatibleMethodOverride]
    for event_dataset in event_dataset_integrations:
        if event_dataset.integration not in rule_integrations:
            rule_integrations.append(event_dataset.integration)

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
            stream_mappings = utils.flat_schema_to_index_mapping(flat_schema)
            nested_multifields = find_nested_multifields(stream_mappings)
            for field in nested_multifields:
                field_name = str(field).split(".fields.")[0].replace(".", ".properties.") + ".fields"
                log(
                    f"Warning: Nested multi-field `{field}` found in `{integration}-{stream}`. "
                    f"Removing parent field from schema for ES|QL validation."
                )
                utils.delete_nested_key_from_dict(stream_mappings, field_name)
            nested_flattened_fields = find_flattened_fields_with_subfields(stream_mappings)
            for field in nested_flattened_fields:
                field_name = str(field).split(".fields.")[0].replace(".", ".properties.") + ".fields"
                log(
                    f"Warning: flattened field `{field}` found in `{integration}-{stream}` with sub fields. "
                    f"Removing parent field from schema for ES|QL validation."
                )
                utils.delete_nested_key_from_dict(stream_mappings, field_name)
            utils.combine_dicts(integration_mappings, stream_mappings)
            index_lookup[f"{integration}-{stream}"] = stream_mappings

    return integration_mappings, index_lookup


def create_remote_indices(
    elastic_client: Elasticsearch,
    existing_mappings: dict[str, Any],
    index_lookup: dict[str, Any],
    log: Callable[[str], None],
) -> str:
    """Create remote indices for validation and return the index string."""
    suffix = str(int(time.time() * 1000))
    test_index = f"rule-test-index-{suffix}"
    response = create_index_with_index_mapping(elastic_client, test_index, existing_mappings)
    log(f"Index `{test_index}` created: {response}")
    full_index_str = test_index

    # create all integration indices
    for index, properties in index_lookup.items():
        ind_index_str = f"test-{index.rstrip('*')}{suffix}"
        response = create_index_with_index_mapping(elastic_client, ind_index_str, properties)
        log(f"Index `{ind_index_str}` created: {response}")
        full_index_str = f"{full_index_str}, {ind_index_str}"

    return full_index_str


def execute_query_against_indices(
    elastic_client: Elasticsearch,
    query: str,
    test_index_str: str,
    log: Callable[[str], None],
    delete_indices: bool = True,
) -> tuple[list[Any], ObjectApiResponse[Any]]:
    """Execute the ESQL query against the test indices on a remote Stack and return the columns."""
    try:
        log(f"Executing a query against `{test_index_str}`")
        response = elastic_client.esql.query(query=query)
        log(f"Got query response: {response}")
        query_columns = response.get("columns", [])
    except BadRequestError as e:
        error_msg = str(e)
        if "parsing_exception" in error_msg:
            raise EsqlSyntaxError(str(e), elastic_client) from e
        raise EsqlSemanticError(str(e), elastic_client) from e
    finally:
        if delete_indices or misc.getdefault("skip_empty_index_cleanup")():
            for index_str in test_index_str.split(","):
                response = elastic_client.indices.delete(index=index_str.strip())
                log(f"Test index `{index_str}` deleted: {response}")

    query_column_names = [c["name"] for c in query_columns]
    log(f"Got query columns: {', '.join(query_column_names)}")
    return query_columns, response


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
    """Recursively search for fields of type 'flattened' that have a 'fields' key in Elasticsearch mappings."""
    flattened_fields_with_subfields = []

    for field, properties in mapping.items():
        current_path = f"{path}.{field}" if path else field

        if isinstance(properties, dict):
            # Check if the field is of type 'flattened' and has a 'fields' key
            if properties.get("type") == "flattened" and "fields" in properties:  # type: ignore[reportUnknownVariableType]
                flattened_fields_with_subfields.append(current_path)  # type: ignore[reportUnknownVariableType]

            # Recurse into subfields
            if "properties" in properties:
                flattened_fields_with_subfields.extend(  # type: ignore[reportUnknownVariableType]
                    find_flattened_fields_with_subfields(properties["properties"], current_path)  # type: ignore[reportUnknownVariableType]
                )

    return flattened_fields_with_subfields  # type: ignore[reportUnknownVariableType]


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
    elastic_client: Elasticsearch,
    indices: list[str],
    event_dataset_integrations: list[utils.EventDataset],
    metadata: RuleMeta,
    stack_version: str,
    log: Callable[[str], None],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Prepare index mappings for the given indices and rule integrations."""
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

    # Combine existing and integration mappings into a single mapping dict
    combined_mappings: dict[str, Any] = {}
    utils.combine_dicts(combined_mappings, existing_mappings)
    utils.combine_dicts(combined_mappings, integration_mappings)

    # Load non-ecs schema and convert to index mapping format (nested schema)
    non_ecs_mapping: dict[str, Any] = {}
    non_ecs = ecs.get_non_ecs_schema()
    for index in indices:
        non_ecs_mapping.update(non_ecs.get(index, {}))
    non_ecs_mapping = ecs.flatten(non_ecs_mapping)
    non_ecs_mapping = utils.convert_to_nested_schema(non_ecs_mapping)
    if not combined_mappings and not non_ecs_mapping:
        raise ValueError("No mappings found")
    index_lookup.update({"rule-non-ecs-index": non_ecs_mapping})

    # Load ECS in an index mapping format (nested schema)
    current_version = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
    ecs_schema = get_ecs_schema_mappings(current_version)

    index_lookup.update({"rule-ecs-index": ecs_schema})

    return existing_mappings, index_lookup, combined_mappings

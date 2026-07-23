# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Validation logic for rules containing queries."""

import re
import time
from collections.abc import Callable
from copy import deepcopy
from typing import Any

from elastic_transport import ObjectApiResponse
from elasticsearch import Elasticsearch  # type: ignore[reportMissingTypeStubs]
from elasticsearch.exceptions import BadRequestError
from semver import Version

from . import ecs, integrations, misc, utils
from .config import load_current_package_version
from .esql import EventDataset
from .esql_errors import (
    EsqlKibanaBaseError,
    EsqlSchemaError,
    EsqlSyntaxError,
    EsqlTypeMismatchError,
    EsqlUnknownIndexError,
    EsqlUnsupportedTypeError,
    cleanup_empty_indices,
)
from .integrations import (
    load_integrations_manifests,
    load_integrations_schemas,
)
from .rule import RuleMeta
from .schemas import get_stack_schemas
from .schemas.definitions import HTTP_STATUS_BAD_REQUEST
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
    """Resolve the packages a rule references and their data stream restrictions."""
    # Restrictions only apply to packages referenced through event.dataset values but not
    # rule metadata; metadata packages contribute all of their data streams.
    packages = list(rule_integrations)
    dataset_restriction: dict[str, list[str]] = {}

    # Process restrictions, note we need this for loops to be separate
    for event_dataset in event_dataset_integrations:
        # Ensure the integration is in rule_integrations
        if event_dataset.package not in packages:
            dataset_restriction.setdefault(event_dataset.package, []).append(event_dataset.integration)
    for event_dataset in event_dataset_integrations:
        if event_dataset.package not in packages:
            packages.append(event_dataset.package)

    return packages, dataset_restriction


def rule_datasets_by_package(
    rule_integrations: list[str],
    event_dataset_integrations: list[EventDataset],
) -> dict[str, list[str | None]]:
    """Map each package a rule references to the data streams the rule is restricted to."""
    # Mirrors prepare_integration_mappings: packages referenced in rule metadata map to
    # [None] (package-wide, all data streams are mapped), and only packages referenced
    # solely through event.dataset values are restricted to the named data streams.
    # event.dataset values are extracted by regex and may sit inside OR branches, so they
    # cannot be trusted to narrow a metadata-referenced package.
    packages, dataset_restriction = resolve_rule_packages(rule_integrations, event_dataset_integrations)
    return {package: list[str | None](dataset_restriction.get(package) or [None]) for package in packages}


def rule_integrations_declare_ecs_fields(
    rule_integrations: list[str],
    event_dataset_integrations: list[EventDataset],
    package_manifests: Any,
    integration_schemas: Any,
    stack_version: str,
) -> bool:
    """Return True when every integration the rule references declares its ECS fields."""
    # Mirrors the KQL/EQL scoping semantics: data streams named by event.dataset are checked
    # individually; packages referenced only through rule metadata are checked package-wide.
    datasets_by_package = rule_datasets_by_package(rule_integrations, event_dataset_integrations)
    if not datasets_by_package:
        return False
    for package, datasets in datasets_by_package.items():
        try:
            package_version, _ = integrations.find_latest_compatible_version(
                package,
                "",
                Version.parse(stack_version),
                package_manifests,
            )
        except ValueError:
            # an unresolvable package keeps the full-ECS fallback for the whole rule
            return False
        for dataset in datasets:
            # packages that inherit ECS via ecs@mappings also keep the full-ECS fallback
            if not integrations.integration_declares_ecs_fields(integration_schemas, package, package_version, dataset):
                return False
    return True


def esql_indices_covered_by_packages(
    indices: list[str],
    rule_integrations: list[str],
    event_dataset_integrations: list[EventDataset],
) -> bool:
    """Return True when every FROM index resolves to one of the rule's integration packages."""
    # Non-integration indices (e.g. auditbeat-*, filebeat-*) are populated by Beats with their
    # own schemas, which the ES|QL mapping build does not model, so rules reading them must
    # keep the full-ECS fallback.
    packages, _ = resolve_rule_packages(rule_integrations, event_dataset_integrations)
    for index in indices:
        if not index.startswith("logs-"):
            return False
        package = re.split(r"[.\-*]", index.removeprefix("logs-"), maxsplit=1)[0]
        if package not in packages:
            return False
    return True


def get_rule_ecs_additions_mappings(
    rule_integrations: list[str],
    event_dataset_integrations: list[EventDataset],
    current_version: Version,
) -> dict[str, Any]:
    """Get index mappings for the override ECS additions of the rule's integrations."""
    # Used instead of the full ECS schema mappings when every integration the rule references
    # declares its ECS fields (strict ECS scoping): only the pipeline/agent-injected fields
    # from integration-ecs-additions.json are mapped on top of the integration schemas.
    addition_fields: set[str] = set()
    for package, datasets in rule_datasets_by_package(rule_integrations, event_dataset_integrations).items():
        for dataset in datasets:
            addition_fields.update(integrations.get_integration_ecs_additions(package, dataset))

    ecs_version = get_stack_schemas()[str(current_version)]["ecs"]
    ecs_flat = ecs.get_schema(ecs_version, name="ecs_flat")
    flat_additions = {field: ecs_flat[field]["type"] for field in sorted(addition_fields) if field in ecs_flat}
    return flat_schema_to_index_mapping(flat_additions)


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

    rule_integrations, dataset_restriction = resolve_rule_packages(rule_integrations, event_dataset_integrations)

    for integration in rule_integrations:
        package = integration
        package_version, _ = integrations.find_latest_compatible_version(
            package,
            "",
            Version.parse(stack_version),
            package_manifests,
        )
        # Drop the ECS scoping metadata (`_uses_ecs_mappings`, `_ecs_declared`) and ML job
        # lists from the cached schema; only data stream field dicts become index mappings.
        package_schema = {
            stream: {field: value for field, value in stream_schema.items() if not field.startswith("_")}
            for stream, stream_schema in integration_schemas[package][package_version].items()
            if stream != "jobs" and not stream.startswith("_")
        }

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
            raise EsqlSyntaxError(str(e), elastic_client) from None
        if "Unknown column" in error_msg:
            raise EsqlSchemaError(str(e), elastic_client) from None
        if "verification_exception" in error_msg and "unsupported type" in error_msg:
            raise EsqlUnsupportedTypeError(str(e), elastic_client) from None
        if "verification_exception" in error_msg:
            raise EsqlTypeMismatchError(str(e), elastic_client) from None
        raise EsqlKibanaBaseError(str(e), elastic_client) from None
    if delete_indices or not misc.getdefault("skip_empty_index_cleanup")():
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
    elastic_client: Elasticsearch,
    indices: list[str],
    event_dataset_integrations: list[EventDataset],
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

    # Load ECS in an index mapping format (nested schema). When every integration the rule
    # references declares its ECS fields (strict ECS scoping), only the override additions
    # are mapped instead of the full ECS schema, mirroring the KQL/EQL validation behavior.
    current_version = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
    if esql_indices_covered_by_packages(
        indices, rule_integrations, event_dataset_integrations
    ) and rule_integrations_declare_ecs_fields(
        rule_integrations, event_dataset_integrations, package_manifests, integration_schemas, stack_version
    ):
        log("All rule integrations declare their ECS fields; scoping ECS mappings to override additions")
        ecs_schema = get_rule_ecs_additions_mappings(rule_integrations, event_dataset_integrations, current_version)
    else:
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

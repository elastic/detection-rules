# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Validation logic for rules containing queries."""

import re
import typing
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from functools import cached_property, wraps
from typing import Any, cast

import eql  # type: ignore[reportMissingTypeStubs]
import esql
import kql  # type: ignore[reportMissingTypeStubs]
from eql import ast  # type: ignore[reportMissingTypeStubs]
from eql.parser import (  # type: ignore[reportMissingTypeStubs]
    KvTree,
    LarkToEQL,
    NodeInfo,
    TypeHint,
)
from eql.parser import _parse as base_parse  # type: ignore[reportMissingTypeStubs]
from semver import Version

from . import ecs, endgame
from .beats import get_datasets_and_modules, parse_beats_from_index
from .config import CUSTOM_RULES_DIR, load_current_package_version, parse_rules_config
from .custom_schemas import update_auto_generated_schema
from .esql import (
    collect_index_field_schemas,
    collect_lookup_index_field_schemas,
    collect_package_fields_for_indices,
    get_esql_lookup_join_targets,
    get_esql_query_event_dataset_integrations,
    get_esql_query_indices,
    infer_packages_from_indices,
    lookup_index_uses_ecs,
    normalize_dataset_package,
)
from .esql_errors import (
    EsqlSchemaError as DrEsqlSchemaError,
)
from .esql_errors import (
    EsqlSemanticError as DrEsqlSemanticError,
)
from .esql_errors import (
    EsqlSyntaxError as DrEsqlSyntaxError,
)
from .esql_errors import EsqlTypeMismatchError
from .index_mappings import (
    esql_indices_covered_by_packages,
    get_rule_integrations,
    validate_offline_esql_from_indices,
)
from .integrations import (
    find_latest_compatible_version,
    find_latest_integration_patch_for_minor,
    get_integration_schema_data,
    load_integrations_manifests,
    load_integrations_schemas,
    parse_datasets,
)
from .rule import (
    EQLRuleData,
    QueryRuleData,
    QueryValidator,
    RuleMeta,
    TOMLRuleContents,
    set_eql_config,
    set_esql_config,
)
from .schemas import get_stack_schemas

EQL_ERROR_TYPES = (
    eql.EqlCompileError
    | eql.EqlError
    | eql.EqlParseError
    | eql.EqlSchemaError
    | eql.EqlSemanticError
    | eql.EqlSyntaxError
    | eql.EqlTypeMismatchError
)
KQL_ERROR_TYPES = kql.KqlCompileError | kql.KqlParseError
RULES_CONFIG = parse_rules_config()


@dataclass(frozen=True)
class ValidationTarget:
    """A single validation target for a query."""

    query_text: str
    schema: Any
    err_trailer: str
    min_stack_version: str
    kind: str  # "integration" or "stack"
    # Optional context about schema selection
    beat_types: list[str] | None = None
    integration_types: list[str] | None = None


def deduplicate_validation_targets(targets: list[ValidationTarget]) -> list[ValidationTarget]:
    """Keep only the first target for each distinct parser input."""
    unique: list[ValidationTarget] = []
    seen: dict[tuple[Any, ...], list[dict[str, Any]]] = {}

    for target in targets:
        schema = target.schema
        if isinstance(schema, dict):
            fields: dict[str, Any] | None = cast("dict[str, Any]", schema)
        elif isinstance(schema, ecs.KqlSchema2Eql):
            fields = schema.kql_schema
        elif isinstance(schema, endgame.EndgameSchema):
            fields = schema.endgame_schema
        else:
            unique.append(target)
            continue

        # Trailers / beat/integration metadata only affect error reporting.
        schema_type = type(cast("object", schema))
        key = (target.query_text, target.min_stack_version, schema_type)
        schemas = seen.setdefault(key, [])
        if fields in schemas:
            continue

        schemas.append(fields)
        unique.append(target)

    return unique


class ExtendedTypeHint(Enum):
    IP = "ip"

    @classmethod
    def primitives(cls):  # noqa: ANN206
        """Get all primitive types."""
        return TypeHint.Boolean, TypeHint.Numeric, TypeHint.Null, TypeHint.String, ExtendedTypeHint.IP

    def is_primitive(self) -> bool:
        """Check if a type is a primitive."""
        return self in self.primitives()


@typing.no_type_check
def custom_in_set(self: LarkToEQL, node: KvTree) -> NodeInfo:
    """Override and address the limitations of the eql in_set method."""
    response = self.visit(node.child_trees)
    if not response:
        raise ValueError("Child trees are not provided")

    outer, container = response

    if not outer.validate_type(ExtendedTypeHint.primitives()):
        # can't compare non-primitives to sets
        raise self._type_error(outer, ExtendedTypeHint.primitives())

    # Check that everything inside the container has the same type as outside
    error_message = "Unable to compare {expected_type} to {actual_type}"
    for inner in container:
        if not inner.validate_type(outer):
            raise self._type_error(inner, outer, error_message)

    if self._elasticsearch_syntax and hasattr(outer, "type_info"):
        # Check edge case of in_set and ip/string comparison
        outer_type = outer.type_info
        if isinstance(self._schema, ecs.KqlSchema2Eql):
            type_hint = self._schema.kql_schema.get(str(outer.node), "unknown")
            if hasattr(self._schema, "type_mapping") and type_hint == "ip":
                outer.type_info = ExtendedTypeHint.IP
                for inner in container:
                    if not inner.validate_type(outer):
                        raise self._type_error(inner, outer, error_message)

        # reset the type
        outer.type_info = outer_type

    # This will always evaluate to true/false, so it should be a boolean
    term = ast.InSet(outer.node, [c.node for c in container])
    nullable = outer.nullable or any(c.nullable for c in container)
    return NodeInfo(term, TypeHint.Boolean, nullable=nullable, source=node)


def custom_base_parse_decorator(func: Callable[..., Any]) -> Callable[..., Any]:
    """Override and address the limitations of the eql in_set method."""

    @wraps(func)
    def wrapper(query: str, start: str | None = None, **kwargs: dict[str, Any]) -> Any:
        original_in_set = LarkToEQL.in_set  # type: ignore[reportUnknownMemberType]
        LarkToEQL.in_set = custom_in_set
        try:
            result = func(query, start=start, **kwargs)
        finally:  # Using finally to ensure that the original method is restored
            LarkToEQL.in_set = original_in_set
        return result

    return wrapper


eql.parser._parse = custom_base_parse_decorator(base_parse)  # type: ignore[reportPrivateUsage] # noqa: SLF001


# Integration targets do not union the full ECS schema (packages populate only a subset of it); the hint tells the
# author where a field the package populates without declaring belongs.
INTEGRATION_SCHEMA_HINT = (
    "Only fields the package field files declare (plus the non-ecs-schema.json and integration-emitted-ecs-schema.json "
    "entries for the rule's index patterns) are accepted; the full ECS schema is not unioned. Add genuinely populated "
    "ECS fields to detection_rules/etc/integration-emitted-ecs-schema.json and fields outside ECS to "
    "detection_rules/etc/non-ecs-schema.json"
)


class KQLValidator(QueryValidator):
    """Specific fields for KQL query event types."""

    @cached_property
    def ast(self) -> kql.ast.Expression:  # type: ignore[reportIncompatibleMethod]
        return kql.parse(self.query, normalize_kql_keywords=RULES_CONFIG.normalize_kql_keywords)  # type: ignore[reportUnknownMemberType]

    @cached_property
    def unique_fields(self) -> list[str]:  # type: ignore[reportIncompatibleMethod]
        return kql.get_field_names(self.ast)  # type: ignore[reportUnknownVariableType, reportUnknownMemberType]

    def auto_add_field(self, validation_checks_error: kql.errors.KqlParseError, index_or_dataview: str) -> None:
        """Auto add a missing field to the schema."""
        field_name = extract_error_field(self.query, validation_checks_error)
        if not field_name:
            raise ValueError("No fied name found for the error")
        field_type = ecs.get_all_flattened_schema().get(field_name)
        update_auto_generated_schema(index_or_dataview, field_name, field_type)

    def to_eql(self) -> eql.ast.Expression:
        return kql.to_eql(self.query)  # type: ignore[reportUnknownVariableType]

    def _prepare_integration_schema(
        self, base_schema: dict[str, Any], stack_version: str, data: QueryRuleData
    ) -> dict[str, Any]:
        """Augment a base integration schema with index/custom/endpoint fields."""
        schema = dict(base_schema)
        for index_name in data.index_or_dataview:
            schema.update(**ecs.flatten(ecs.get_index_schema(index_name)))
        if data.index and CUSTOM_RULES_DIR:
            for index_name in data.index_or_dataview:
                schema.update(**ecs.flatten(ecs.get_custom_index_schema(index_name, stack_version)))
        schema.update(**ecs.flatten(ecs.get_endpoint_schemas()))
        return schema

    def build_validation_plan(self, data: QueryRuleData, meta: RuleMeta) -> list[ValidationTarget]:
        """Return a unified list of validation targets for this query.

        Integration targets: union of integration schemas per stack version (if integrations are available)
        Stack targets: ECS/beats/endgame schemas per supported stack version
        """
        targets: list[ValidationTarget] = []

        # Build integration-based targets if available
        packages_manifest = load_integrations_manifests()
        package_integrations = TOMLRuleContents.get_packaged_integrations(data, meta, packages_manifest)

        if package_integrations:
            combined_by_stack: dict[str, dict[str, Any]] = {}
            ecs_by_stack: dict[str, str] = {}
            packages_by_stack: dict[str, set[str]] = {}

            for integ in get_integration_schema_data(data, meta, package_integrations):
                stack_version = integ["stack_version"]
                ecs_version = integ["ecs_version"]
                package = integ["package"]
                schema = self._prepare_integration_schema(integ["schema"], stack_version, data)

                _ = ecs_by_stack.setdefault(stack_version, ecs_version)
                _ = packages_by_stack.setdefault(stack_version, set()).add(package)
                combined_by_stack.setdefault(stack_version, {}).update(schema)

            for stack_version, schema_dict in combined_by_stack.items():
                ecs_version = ecs_by_stack.get(stack_version, "unknown")
                pkgs_set = packages_by_stack.get(stack_version, set())
                pkgs = ", ".join(sorted(pkgs_set))
                err_trailer = (
                    "Try adding event.module or event.dataset to specify integration module\n\n"
                    f"Checked against packages [{pkgs}]; stack: {stack_version}; ecs: {ecs_version}\n"
                    f"{INTEGRATION_SCHEMA_HINT}\n"
                    f"rule: {data.name} - {data.rule_id}"
                )
                targets.append(
                    ValidationTarget(
                        query_text=self.query,
                        schema=schema_dict,
                        err_trailer=err_trailer,
                        min_stack_version=str(meta.min_stack_version or load_current_package_version()),
                        beat_types=None,
                        integration_types=sorted(pkgs_set),
                        kind="integration",
                    )
                )

        # Build stack targets only when TOML indicates stack-based validation is needed
        # - If no integration packages resolved, include stack targets as fallback
        # - Or when beats or endgame indices are present
        beat_types_present = parse_beats_from_index(data.index_or_dataview) if data.index_or_dataview else []
        endgame_present = bool(data.index_or_dataview and "endgame-*" in data.index_or_dataview)
        should_add_stack_targets = (not package_integrations) or (bool(beat_types_present) or endgame_present)
        if should_add_stack_targets:
            for stack_version, mapping in meta.get_validation_stack_versions().items():
                beats_version = mapping["beats"]
                ecs_version = mapping["ecs"]
                beat_types, _, schema = self.get_beats_schema(data.index_or_dataview, beats_version, ecs_version)
                err_trailer = (
                    f"stack: {stack_version}, beats: {beats_version}, ecs: {ecs_version}\n"
                    f"rule: {data.name} - {data.rule_id}"
                )
                targets.append(
                    ValidationTarget(
                        query_text=self.query,
                        schema=schema,
                        err_trailer=err_trailer,
                        min_stack_version=str(meta.min_stack_version or load_current_package_version()),
                        beat_types=beat_types,
                        integration_types=None,
                        kind="stack",
                    )
                )

        return deduplicate_validation_targets(targets)

    def validate(self, data: QueryRuleData, meta: RuleMeta, max_attempts: int = 10) -> None:  # type: ignore[reportIncompatibleMethod]
        """Validate the query using computed schema combinations, favoring integrations when present."""
        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            return

        if data.language == "lucene":
            return

        for _ in range(max_attempts):
            all_targets = self.build_validation_plan(data, meta)
            has_integration = any(t.kind == "integration" for t in all_targets)
            # Order targets: integrations first (if any), then stack; otherwise just stack
            ordered_targets = (
                [t for t in all_targets if t.kind == "integration"] + [t for t in all_targets if t.kind == "stack"]
                if has_integration
                else [t for t in all_targets if t.kind == "stack"]
            )
            retry = False
            for t in ordered_targets:
                exc = self.validate_query_text_with_schema(
                    schema=t.schema,
                    err_trailer=t.err_trailer,
                    beat_types=t.beat_types,
                    integration_types=t.integration_types,
                )
                if exc is None:
                    continue

                # Attempt auto-add for missing fields when enabled
                if (
                    (exc.error_msg == "Unknown field" or "Field not recognized" in exc.error_msg)  # type: ignore[reportAttributeAccessIssue]
                    and RULES_CONFIG.auto_gen_schema_file
                    and data.index_or_dataview
                ):
                    self.auto_add_field(exc, data.index_or_dataview[0])  # type: ignore[reportArgumentType]
                    retry = True
                    break

                # Raise enriched error from helper
                raise exc
            if not retry:
                # All targets passed
                return

        raise ValueError(f"Maximum validation attempts exceeded for {data.rule_id} - {data.name}")

    def validate_query_text_with_schema(
        self,
        *,
        schema: dict[str, Any],
        err_trailer: str,
        beat_types: list[str] | None,
        integration_types: list[str] | None,
    ) -> KQL_ERROR_TYPES | None:
        """Validate the KQL query text against a given schema and return an enriched error if it fails."""
        try:
            kql.parse(  # type: ignore[reportUnknownMemberType]
                self.query,
                schema=schema,
                normalize_kql_keywords=RULES_CONFIG.normalize_kql_keywords,
            )
        except kql.KqlParseError as exc:
            # Compose an informative trailer
            trailer_parts: list[str] = []
            if exc.error_msg == "Unknown field" and beat_types:
                trailer_parts.insert(
                    0,
                    "Try adding event.module or data_stream.dataset to specify beats module",
                )
            if integration_types:
                pkgs = ", ".join(integration_types)
                trailer_parts.append(f"integration_types: [{pkgs}]")
            if beat_types:
                trailer_parts.append(f"beat_types: [{', '.join(beat_types)}]")

            if err_trailer:
                trailer_parts.append(err_trailer)

            trailer = "\n\n".join(tp for tp in trailer_parts if tp)

            return kql.KqlParseError(
                exc.error_msg,  # type: ignore[reportUnknownArgumentType]
                exc.line,  # type: ignore[reportUnknownArgumentType]
                exc.column,  # type: ignore[reportUnknownArgumentType]
                exc.source,  # type: ignore[reportUnknownArgumentType]
                len(exc.caret.lstrip()),
                trailer=trailer or None,  # type: ignore[reportUnknownArgumentType]
            )
        else:
            return None


class EQLValidator(QueryValidator):
    """Specific fields for EQL query event types."""

    @cached_property
    def ast(self) -> eql.ast.Expression:  # type: ignore[reportIncompatibleMethodOverrichemas]
        latest_version = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
        cfg = set_eql_config(str(latest_version))
        with eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions, eql.parser.skip_optimizations, cfg:
            return eql.parse_query(self.query)  # type: ignore[reportUnknownVariableType]

    def text_fields(self, eql_schema: ecs.KqlSchema2Eql | endgame.EndgameSchema) -> list[str]:
        """Return a list of fields of type text."""
        from kql.parser import elasticsearch_type_family  # type: ignore[reportMissingTypeStubs]

        schema = eql_schema.kql_schema if isinstance(eql_schema, ecs.KqlSchema2Eql) else eql_schema.endgame_schema

        return [f for f in self.unique_fields if elasticsearch_type_family(schema.get(f)) == "text"]  # type: ignore[reportArgumentType]

    @cached_property
    def unique_fields(self) -> list[str]:  # type: ignore[reportIncompatibleMethodOverride]
        return list({str(f) for f in self.ast if isinstance(f, eql.ast.Field)})  # type: ignore[reportUnknownVariableType]

    def auto_add_field(
        self, validation_checks_error: eql.EqlParseError, index_or_dataview: str, field: str | None = None
    ) -> None:
        """Auto add a missing field to the schema."""
        field_name = field
        if not field:
            field_name = extract_error_field(self.query, validation_checks_error)
        if not field_name:
            raise ValueError("No field name found")
        field_type = ecs.get_all_flattened_schema().get(field_name)
        update_auto_generated_schema(index_or_dataview, field_name, field_type)

    def _build_synthetic_sequence_from_subquery(self, subquery: "ast.SubqueryBy") -> str:
        """Build a minimal synthetic sequence containing the subquery for validation."""
        subquery_text = str(subquery)
        join_fields = ", ".join(map(str, getattr(subquery, "join_values", []) or []))
        dummy_by = f" by {join_fields}" if join_fields else ""
        return f"sequence\n  {subquery_text}\n  [any where true]{dummy_by}"

    def build_validation_plan(self, data: "QueryRuleData", meta: RuleMeta) -> list[ValidationTarget]:  # noqa: PLR0912 PLR0915
        """Return a unified list of validation targets for EQL validation.

        Non-sequence: accumulate integration schemas per stack, optionally add stack schemas.
        Sequence: build per-subquery integration targets using synthetic sequences; for datasetless
        subqueries without metadata integrations, add per-subquery stack targets; optionally add
        whole-query stack schemas when indicated by TOML (indices present) or no integrations.
        """
        targets: list[ValidationTarget] = []

        is_sequence = getattr(data, "is_sequence", False)
        min_stack_str = str(meta.min_stack_version or load_current_package_version())
        # Sequence planning below may add per-subquery stack targets when needed

        packages_manifest = load_integrations_manifests()
        packaged_integrations = TOMLRuleContents.get_packaged_integrations(data, meta, packages_manifest)
        beat_types_present = parse_beats_from_index(data.index_or_dataview) if data.index_or_dataview else []
        endgame_present = bool(data.index_or_dataview and "endgame-*" in data.index_or_dataview)

        # Helper for union-by-stack integration targets
        def add_accumulated_integration_targets(query_text: str, packaged: list[dict[str, Any]], context: str) -> None:
            """Add integration-based validation targets by accumulating schemas per stack version."""
            combined_by_stack: dict[str, dict[str, Any]] = {}
            ecs_by_stack: dict[str, str] = {}
            packages_by_stack: dict[str, set[str]] = {}
            for integ in get_integration_schema_data(data, meta, packaged):
                stack_version = integ["stack_version"]
                ecs_version = integ["ecs_version"]
                package = integ["package"]
                # copy: the integration schema is memoized and shared across rules
                schema = dict(integ["schema"])
                # prepare with index/custom/endpoint fields
                if data.index_or_dataview:
                    for index_name in data.index_or_dataview:  # type: ignore[reportArgumentType]
                        schema.update(**ecs.flatten(ecs.get_index_schema(index_name)))
                    if data.index and CUSTOM_RULES_DIR:
                        for index_name in data.index_or_dataview:
                            schema.update(**ecs.flatten(ecs.get_custom_index_schema(index_name, stack_version)))
                schema.update(**ecs.flatten(ecs.get_endpoint_schemas()))

                # Do not merge Beats into integration schemas; validate independently via stack targets

                _ = ecs_by_stack.setdefault(stack_version, ecs_version)
                packages_by_stack.setdefault(stack_version, set()).add(package)
                combined_by_stack.setdefault(stack_version, {}).update(schema)

            for stack_version, schema_dict in combined_by_stack.items():
                ecs_version = ecs_by_stack.get(stack_version, "unknown")
                pkgs_set = packages_by_stack.get(stack_version, set())
                pkgs = ", ".join(sorted(pkgs_set))
                err_trailer = (
                    f"{context}\nChecked against packages [{pkgs}]; stack: {stack_version}; ecs: {ecs_version}\n"
                    f"{INTEGRATION_SCHEMA_HINT}\n"
                    f"rule: {data.name} - {data.rule_id}"
                )
                targets.append(
                    ValidationTarget(
                        query_text=query_text,
                        schema=ecs.KqlSchema2Eql(schema_dict),
                        err_trailer=err_trailer,
                        min_stack_version=min_stack_str,
                        beat_types=None,
                        integration_types=sorted(pkgs_set),
                        kind="integration",
                    )
                )

        # Helper to add Beats/ECS (and optionally Endgame) stack targets for a given query text
        def add_stack_targets(query_text: str, include_endgame: bool) -> None:
            for stack_version, mapping in meta.get_validation_stack_versions().items():
                beats_version = mapping["beats"]
                ecs_version = mapping["ecs"]
                endgame_version = mapping["endgame"]

                beat_types, _, kql_schema = self.get_beats_schema(data.index_or_dataview, beats_version, ecs_version)
                err_trailer = (
                    f"stack: {stack_version}, beats: {beats_version},ecs: {ecs_version}, endgame: {endgame_version}\n"
                    f"rule: {data.name} - {data.rule_id}"
                )
                # ECS (+beats if present)
                targets.append(
                    ValidationTarget(
                        query_text=query_text,
                        schema=ecs.KqlSchema2Eql(kql_schema),
                        err_trailer=err_trailer,
                        min_stack_version=min_stack_str,
                        beat_types=beat_types,
                        integration_types=None,
                        kind="stack",
                    )
                )
                # Optionally add Endgame
                if include_endgame:
                    endgame_schema = self.get_endgame_schema(data.index_or_dataview, endgame_version)
                    if endgame_schema:
                        targets.append(
                            ValidationTarget(
                                query_text=query_text,
                                schema=endgame_schema,
                                err_trailer=err_trailer,
                                min_stack_version=min_stack_str,
                                beat_types=None,
                                integration_types=None,
                                kind="stack",
                            )
                        )

        # Sequence queries: per-subquery validation
        if is_sequence:
            sequence: ast.Sequence = self.ast.first  # type: ignore[reportAttributeAccessIssue]
            for subquery in sequence.queries:  # type: ignore[reportUnknownVariableType]
                subquery_datasets, _ = get_datasets_and_modules(subquery)  # type: ignore[reportUnknownVariableType]
                synthetic_sequence = self._build_synthetic_sequence_from_subquery(subquery)  # type: ignore[reportArgumentType]

                if subquery_datasets:
                    subquery_pkg_ints = parse_datasets(list(subquery_datasets), packages_manifest)
                    # Per-subquery: validate each integration combination individually (no accumulation)
                    for integ in get_integration_schema_data(data, meta, subquery_pkg_ints):
                        package = integ["package"]
                        package_version = integ["package_version"]
                        stack_version = integ["stack_version"]
                        ecs_version = integ["ecs_version"]
                        # copy: the integration schema is memoized and shared across rules
                        schema_dict = dict(integ["schema"])

                        # prepare schema
                        if data.index_or_dataview:
                            for index_name in data.index_or_dataview:  # type: ignore[reportArgumentType]
                                schema_dict.update(**ecs.flatten(ecs.get_index_schema(index_name)))
                            if data.index and CUSTOM_RULES_DIR:
                                for index_name in data.index_or_dataview:
                                    schema_dict.update(
                                        **ecs.flatten(ecs.get_custom_index_schema(index_name, stack_version))
                                    )
                        schema_dict.update(**ecs.flatten(ecs.get_endpoint_schemas()))

                        err_trailer = (
                            "Subquery schema mismatch. "
                            f"package: {package}, package_version: {package_version}, "
                            f"stack: {stack_version}, ecs: {ecs_version}\n"
                            f"{INTEGRATION_SCHEMA_HINT}\n"
                            f"rule: {data.name} - {data.rule_id}"
                        )
                        targets.append(
                            ValidationTarget(
                                query_text=synthetic_sequence,
                                schema=ecs.KqlSchema2Eql(schema_dict),
                                err_trailer=err_trailer,
                                min_stack_version=min_stack_str,
                                beat_types=None,
                                integration_types=[package],
                                kind="integration",
                            )
                        )
                        # Additionally validate this subquery against Beats/ECS if beats indices are present
                        if beat_types_present:
                            add_stack_targets(synthetic_sequence, include_endgame=False)
                else:
                    # Datasetless subquery: try metadata integrations first, else add per-subquery stack targets
                    meta_integrations = get_rule_integrations(meta)

                    if meta_integrations:
                        meta_pkg_ints = [
                            {"package": pkg, "integration": None}
                            for pkg in meta_integrations
                            if pkg in packages_manifest
                        ]
                        add_accumulated_integration_targets(
                            synthetic_sequence,
                            meta_pkg_ints,
                            "Datasetless subquery validation against metadata integrations",
                        )
                        # Also validate datasetless subquery against Beats/ECS if beats indices are present
                        if beat_types_present:
                            add_stack_targets(synthetic_sequence, include_endgame=False)
                    else:
                        # Add stack targets for this datasetless subquery
                        add_stack_targets(synthetic_sequence, include_endgame=True)

        elif packaged_integrations:
            # Non-sequence queries: accumulate integrations per stack if available
            add_accumulated_integration_targets(
                self.query,
                packaged_integrations,
                "Try adding event.module or event.dataset to specify integration module",
            )

        # Stack targets for whole query:
        # - always when no integrations are resolved; OR
        # - for non-sequence queries when beats or endgame indices are present
        need_stack_targets = (not packaged_integrations) or (
            (not is_sequence) and (beat_types_present or endgame_present)
        )
        if need_stack_targets:
            add_stack_targets(self.query, include_endgame=True)

        return deduplicate_validation_targets(targets)

    def validate(self, data: "QueryRuleData", meta: RuleMeta, max_attempts: int = 10) -> None:  # type: ignore[reportIncompatibleMethodOverride]
        """Validate an EQL query using a unified plan of schema combinations."""
        # base field declaration
        field = None
        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            return

        if data.language == "lucene":
            return

        # Validate rule type configuration fields against ECS schema
        set_fields, has_invalid = self.validate_rule_type_configurations(data, meta)  # type: ignore[reportArgumentType]
        if has_invalid and set_fields:
            raise ValueError(f"Rule type configuration fields not in ECS schema: {', '.join(set_fields)}")

        for _ in range(max_attempts):
            all_targets = self.build_validation_plan(data, meta)
            has_integration = any(t.kind == "integration" for t in all_targets)
            # Order targets: integrations first (if any), then stack; otherwise just stack
            ordered_targets = (
                [t for t in all_targets if t.kind == "integration"] + [t for t in all_targets if t.kind == "stack"]
                if has_integration
                else [t for t in all_targets if t.kind == "stack"]
            )
            first_error: EQL_ERROR_TYPES | ValueError | None = None
            for t in ordered_targets:
                exc, field = self.validate_query_text_with_schema(
                    t.query_text,
                    t.schema,
                    err_trailer=t.err_trailer,
                    min_stack_version=t.min_stack_version,
                    beat_types=t.beat_types,
                    integration_types=t.integration_types,
                )
                if exc is not None:
                    first_error = exc
                    break

            if first_error is None:
                # All targets passed
                return

            # Attempt auto-add only when unknown field and enabled; then retry
            if (
                isinstance(first_error, eql.EqlParseError)
                and "Field not recognized" in str(first_error)
                and RULES_CONFIG.auto_gen_schema_file
                and data.index_or_dataview
            ):
                self.auto_add_field(first_error, data.index_or_dataview[0], field=field)  # type: ignore[reportArgumentType]
                continue

            # Raise the enriched parse error (includes target trailer + metadata)
            raise first_error

        raise ValueError(f"Maximum validation attempts exceeded for {data.rule_id} - {data.name}")

    def validate_query_text_with_schema(  # noqa: PLR0913, PLR0917
        self,
        query_text: str,
        schema: ecs.KqlSchema2Eql | endgame.EndgameSchema,
        err_trailer: str,
        min_stack_version: str,
        beat_types: list[str] | None = None,
        integration_types: list[str] | None = None,
    ) -> tuple[EQL_ERROR_TYPES | ValueError | None, str | None]:
        """Validate the provided EQL query text against the schema (variant of validate_query_with_schema)."""
        try:
            config = set_eql_config(min_stack_version)
            with config, schema, eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
                _ = eql.parse_query(query_text)  # type: ignore[reportUnknownMemberType]
        except eql.EqlParseError as exc:
            message = exc.error_msg
            trailer_parts: list[str] = []
            # If the error is an unknown field and the field was referenced as optional (prefixed with '?'),
            # treat this target as non-fatal to honor EQL optional semantics.

            # To support EQL sequence and sub query validation we need to return this field to overwrite
            # what would have been parsed via auto_add_field as the error message and query may be out of sync
            # depending on how the method is called.
            field = extract_error_field(query_text, exc)
            if (
                field
                and ("Unknown field" in message or "Field not recognized" in message)
                and f"?{field}" in self.query
            ):
                return None, field
            if "Unknown field" in message and beat_types:
                trailer_parts.insert(0, "Try adding event.module or event.dataset to specify beats module")
            elif "Field not recognized" in message and isinstance(schema, ecs.KqlSchema2Eql):
                text_fields = self.text_fields(schema)
                if text_fields:
                    fields_str = ", ".join(text_fields)
                    trailer_parts.insert(0, f"eql does not support text fields: {fields_str}")

            # Surface integration packages if available
            if integration_types:
                pkgs = ", ".join(integration_types)
                trailer_parts.append(f"integration_types: [{pkgs}]")
            # Surface beat types if available (stack plan)
            if beat_types:
                trailer_parts.append(f"beat_types: [{', '.join(beat_types)}]")

            if err_trailer:
                trailer_parts.append(err_trailer)

            trailer = "\n\n".join(tp for tp in trailer_parts if tp)
            return exc.__class__(
                exc.error_msg,  # type: ignore[reportUnknownArgumentType]
                exc.line,  # type: ignore[reportUnknownArgumentType]
                exc.column,  # type: ignore[reportUnknownArgumentType]
                exc.source,  # type: ignore[reportUnknownArgumentType]
                len(exc.caret.lstrip()),
                trailer=trailer,
            ), field
        except Exception as exc:  # noqa: BLE001
            print(err_trailer)
            return exc, None  # type: ignore[reportReturnType]
        return None, None

    def validate_rule_type_configurations(self, data: EQLRuleData, meta: RuleMeta) -> tuple[list[str], bool]:
        """Validate EQL rule type configurations (timestamp_field, event_category_override, tiebreaker_field).

        Returns a tuple of the list of configured field names (non-empty) and a boolean indicating whether
        any are not present in the ECS schema for the rule's minimum stack version (or current package version).
        """
        configured: list[str] = []
        if data.timestamp_field:
            configured.append(data.timestamp_field)
        if data.event_category_override:
            configured.append(data.event_category_override)
        if data.tiebreaker_field:
            configured.append(data.tiebreaker_field)

        if not configured:
            return [], False

        stack_version = str(meta.min_stack_version or load_current_package_version())
        min_stack_version = str(Version.parse(stack_version, optional_minor_and_patch=True))
        stack_map = get_stack_schemas(stack_version)
        ecs_version = stack_map[min_stack_version]["ecs"]
        schema = ecs.get_schema(ecs_version)

        return configured, any(f not in schema for f in configured)


# Cross-rule caches for offline ES|QL validation (M6).
_ESQL_SCHEMA_DICT_CACHE: dict[tuple[Any, ...], dict[str, Any]] = {}
_ESQL_WARM_STATE = {"warmed": False}


def _warm_esql_offline_caches() -> None:
    """Load heavy integration/ECS artifacts once per process."""
    if _ESQL_WARM_STATE["warmed"]:
        return
    load_integrations_manifests()
    load_integrations_schemas()
    _ESQL_WARM_STATE["warmed"] = True


def _integration_fields_for_indices(  # noqa: PLR0913
    package_integrations: list[Any],
    indices: list[str],
    min_stack: Version,
    packages_manifest: dict[str, Any],
    integrations_schemas: dict[str, Any],
    *,
    allow_fallback: bool = True,
) -> tuple[dict[str, Any], set[str]]:
    """Collect Fleet stream fields that match *indices* for the given packages."""
    fields: dict[str, Any] = {}
    packages: set[str] = set()
    for pk_int in package_integrations:
        package = normalize_dataset_package(str(pk_int["package"]))
        integration = pk_int.get("integration")
        package_schemas = integrations_schemas.get(package, {})
        try:
            package_version, _ = find_latest_compatible_version(
                package,
                integration or "",
                min_stack,
                packages_manifest,
                package_schemas=package_schemas if integration else None,
            )
        except ValueError:
            continue
        if package not in integrations_schemas or package_version not in integrations_schemas[package]:
            continue
        package_schema = integrations_schemas[package][package_version]
        stream_fields = collect_package_fields_for_indices(
            package_schema, package, indices, integration, allow_fallback=allow_fallback
        )
        for field_name, field_type in stream_fields.items():
            fields[field_name] = kql.parser.elasticsearch_type_family(field_type)
        packages.add(package)
    return fields, packages


def _lookup_join_schemas_for_stack(
    lookup_targets: list[str],
    stack_version: str,
    ecs_version: str,
    packages_manifest: dict[str, Any],
    integrations_schemas: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Build ``Schema(lookups=)`` maps without dumping FROM packages onto lookup indices."""
    if not lookup_targets:
        return {}
    parsed_stack = Version.parse(str(stack_version))
    lookup_pkgs = set(infer_packages_from_indices(lookup_targets))
    patch_floor = find_latest_integration_patch_for_minor(lookup_pkgs, parsed_stack.major, parsed_stack.minor)
    min_stack = Version(parsed_stack.major, parsed_stack.minor, max(parsed_stack.patch, patch_floor))
    ecs_flat = ecs.flatten_multi_fields(ecs.get_schema(ecs_version, name="ecs_flat"))
    lookup_index_fields = collect_lookup_index_field_schemas(lookup_targets)
    lookups: dict[str, dict[str, Any]] = {}
    for target in lookup_targets:
        fields: dict[str, Any] = {}
        if lookup_index_uses_ecs(target):
            fields.update(ecs_flat)
        fields.update(lookup_index_fields.get(target, {}))
        inferred = [{"package": pkg, "integration": None} for pkg in infer_packages_from_indices([target])]
        pkg_fields, _ = _integration_fields_for_indices(
            inferred, [target], min_stack, packages_manifest, integrations_schemas
        )
        fields.update(pkg_fields)
        if fields:
            lookups[target] = fields
    return lookups


def _schema_dict_for_from_indices(  # noqa: PLR0913, PLR0917
    from_indices: list[str],
    ecs_flat: dict[str, Any],
    package_integrations: list[Any],
    min_stack: Version,
    packages_manifest: dict[str, Any],
    integrations_schemas: dict[str, Any],
    index_fields: dict[str, Any],
    *,
    include_ecs: bool = True,
) -> tuple[dict[str, Any], set[str]]:
    """Build the FROM schema, one map per index when several patterns are present.

    A single ``FROM a, b`` still unions those maps. Sibling subqueries only see the
    patterns on their own ``FROM``, which the parser narrows when keys contain ``*``.
    Package-covered indices omit the full ECS schema; Beats and uncovered sources keep it.
    """

    def one(
        indices: list[str], *, shared_index_fields: dict[str, Any] | None, allow_fallback: bool
    ) -> tuple[dict[str, Any], set[str]]:
        stream_fields, pkgs = _integration_fields_for_indices(
            package_integrations,
            indices,
            min_stack,
            packages_manifest,
            integrations_schemas,
            allow_fallback=allow_fallback,
        )
        # A name that only looks like a Fleet package (custom data streams) has no
        # field file. Keep full ECS there so host.name and the rest still resolve.
        schema_dict = dict(ecs_flat) if include_ecs or not pkgs else {}
        if shared_index_fields is not None:
            schema_dict.update(shared_index_fields)
        else:
            schema_dict.update(collect_index_field_schemas(indices))
        schema_dict.update(stream_fields)
        return schema_dict, pkgs

    if len(from_indices) <= 1:
        return one(from_indices, shared_index_fields=index_fields, allow_fallback=True)

    combined: dict[str, Any] = {}
    packages: set[str] = set()
    for index in from_indices:
        per_index, pkgs = one([index], shared_index_fields=None, allow_fallback=False)
        combined[index] = per_index
        packages.update(pkgs)
    # ECS includes a field named "type", which makes Schema treat this map as a
    # flat field list. An empty "*" entry is selected with every FROM pattern and
    # keeps the map in multi-index mode without adding columns.
    combined["*"] = {}
    return combined, packages


def _strict_esql_schema(schema_dict: dict[str, Any], lookups: dict[str, dict[str, Any]] | None = None) -> esql.Schema:
    if lookups:
        return esql.Schema(schema_dict, allow_missing=False, lookups=lookups)
    return esql.Schema(schema_dict, allow_missing=False)


class ESQLValidator(QueryValidator):
    """Validate ES|QL queries offline via detection-rules-esql-py."""

    metadata: RuleMeta
    _parsed_tree: Any | None = None
    # Filled after a successful offline plan so required_fields can type integration columns.
    _resolved_field_types: dict[str, str]

    def _parse_tree(self, min_stack_version: str | None = None) -> Any:
        """Parse query with detection-rules-esql-py under the given stack config."""
        stack = min_stack_version or load_current_package_version()
        cfg = set_esql_config(stack)
        # Empty schema for AST-only parse; field checks run in validate() with plan schemas.
        with cfg, esql.Schema({}, allow_missing=True):
            return esql.parse_query(self.query)

    @cached_property
    def ast(self) -> Any:  # type: ignore[reportIncompatibleMethodOverride]
        """Return the AST of the ES|QL query."""
        if self._parsed_tree is None:
            self._parsed_tree = self._parse_tree()
        return self._parsed_tree

    @cached_property
    def unique_fields(self) -> list[str]:  # type: ignore[reportIncompatibleMethodOverride]
        """Return unique field names from the AST."""
        names = set(esql.get_unique_fields(self.ast))
        names.update(self.nested_query_field_names(self.ast))
        return sorted(names)

    @staticmethod
    def _flat_schema_dict(schema: Any) -> dict[str, Any]:
        """Flatten an esql.Schema (or dict) for nested kql/eql schema checks."""
        if isinstance(schema, esql.Schema):
            return dict(schema._fields)  # type: ignore[reportPrivateUsage]
        if isinstance(schema, dict):
            flat: dict[str, Any] = {}
            mapping = cast("dict[Any, Any]", schema)
            for key, value in mapping.items():
                if isinstance(value, str):
                    flat[str(key)] = value
                elif isinstance(value, dict):
                    field_type = cast("dict[str, Any]", value).get("type")
                    flat[str(key)] = field_type if isinstance(field_type, str) else value
                else:
                    flat[str(key)] = value
            return flat
        return {}

    @staticmethod
    def nested_query_field_names(tree: Any) -> set[str]:
        """Union field names from nested KQL()/EQL() payloads (PRD §5.7 metadata merge)."""
        names: set[str] = set()
        for nested in esql.find_nested_queries(tree):
            text = nested.text
            if not text:
                continue
            try:
                if nested.kind == "kql":
                    parsed = kql.parse(text, normalize_kql_keywords=True)  # type: ignore[reportUnknownMemberType]
                    names.update(kql.get_field_names(parsed))  # type: ignore[reportUnknownArgumentType, reportUnknownMemberType]
                elif nested.kind == "eql":
                    with eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
                        try:
                            parsed_q = eql.parse_query(text)  # type: ignore[reportUnknownMemberType]
                        except eql.EqlParseError:
                            parsed_q = eql.parse_expression(text)  # type: ignore[reportUnknownMemberType]
                    names.update(str(f) for f in parsed_q if isinstance(f, eql.ast.Field))  # type: ignore[reportUnknownVariableType]
            except Exception:  # noqa: BLE001, S112 — field merge best-effort; schema path raises
                continue
        return names

    def _validate_nested_queries_with_schema(  # noqa: PLR0912, PLR0913, PLR0917
        self,
        tree: Any,
        schema: Any,
        err_trailer: str,
        min_stack_version: str,
        beat_types: list[str] | None = None,
        integration_types: list[str] | None = None,
    ) -> Exception | None:
        """Schema-validate nested KQL()/EQL() payloads against the ValidationTarget schema.

        Syntax is handled by parse hooks in set_esql_config. This layer mirrors
        KQLValidator / EQLValidator schema checks for the embedded string args.
        """
        nested_queries = esql.find_nested_queries(tree)
        if not nested_queries:
            return None

        flat = self._flat_schema_dict(schema)
        for nested in nested_queries:
            kind = nested.kind
            text = nested.text
            if not text:
                continue
            locus = f"nested {kind.upper()}() at line {nested.line or '?'}, column {nested.column or '?'}"
            trailer_parts = [locus]
            if integration_types:
                trailer_parts.append(f"integration_types: [{', '.join(integration_types)}]")
            if beat_types:
                trailer_parts.append(f"beat_types: [{', '.join(beat_types)}]")
            if err_trailer:
                trailer_parts.append(err_trailer)
            trailer = "\n\n".join(trailer_parts)

            if kind == "kql":
                try:
                    kql.parse(text, schema=flat, normalize_kql_keywords=True)  # type: ignore[reportUnknownMemberType]
                except kql.KqlParseError as exc:
                    error_msg = str(exc.error_msg)  # type: ignore[reportUnknownArgumentType, reportUnknownMemberType]
                    msg = f"{error_msg}\n\n{trailer}"
                    return DrEsqlSchemaError(msg) if "field" in error_msg.lower() else DrEsqlSemanticError(msg)
                except Exception as exc:  # noqa: BLE001
                    return DrEsqlSemanticError(f"{exc}\n\n{trailer}")
            elif kind == "eql":
                eql_schema = ecs.KqlSchema2Eql(flat)
                cfg = set_eql_config(min_stack_version)
                try:
                    with cfg, eql_schema, eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
                        try:
                            _ = eql.parse_query(text)  # type: ignore[reportUnknownMemberType]
                        except eql.EqlParseError:
                            _ = eql.parse_expression(text)  # type: ignore[reportUnknownMemberType]
                except eql.EqlParseError as exc:
                    error_msg = str(exc.error_msg)  # type: ignore[reportUnknownArgumentType, reportUnknownMemberType]
                    msg = f"{error_msg}\n\n{trailer}"
                    return DrEsqlSchemaError(msg) if "field" in error_msg.lower() else DrEsqlSemanticError(msg)
                except Exception as exc:  # noqa: BLE001
                    return DrEsqlSemanticError(f"{exc}\n\n{trailer}")
        return None

    def build_validation_plan(  # noqa: PLR0912, PLR0915
        self, data: "QueryRuleData", meta: RuleMeta
    ) -> list[ValidationTarget]:
        """Build offline validation targets across the release-window stack map."""
        _warm_esql_offline_caches()
        targets: list[ValidationTarget] = []
        packages_manifest = load_integrations_manifests()
        integrations_schemas = load_integrations_schemas()
        package_integrations = TOMLRuleContents.get_packaged_integrations(data, meta, packages_manifest) or []

        event_datasets = get_esql_query_event_dataset_integrations(self.query, tree=self.ast)
        if not package_integrations and event_datasets:
            package_integrations = [{"package": ds.package, "integration": ds.integration} for ds in event_datasets]

        from_indices = get_esql_query_indices(self.query, tree=self.ast)
        lookup_targets = get_esql_lookup_join_targets(self.query, tree=self.ast)
        # Infer Fleet packages from FROM patterns when metadata/datasets are absent
        # (e.g. metrics-* → system) so offline schemas match remote mapping prep.
        # Lookup-index packages stay off this list so they are not unioned into FROM.
        known_packages = {str(p.get("package")) for p in package_integrations if p.get("package")}
        for package in infer_packages_from_indices(from_indices):
            if package not in known_packages:
                package_integrations.append({"package": package, "integration": None})  # type: ignore[reportArgumentType]
                known_packages.add(package)
        index_fields = collect_index_field_schemas(from_indices)
        pkg_key = tuple(
            sorted(
                (normalize_dataset_package(str(p["package"])), p.get("integration"))
                for p in package_integrations
                if p.get("package")
            )
        )
        indices_key = tuple(sorted(from_indices))

        def lookups_for(stack_version: str, ecs_version: str) -> dict[str, dict[str, Any]] | None:
            built = _lookup_join_schemas_for_stack(
                lookup_targets,
                str(stack_version),
                str(ecs_version),
                packages_manifest,
                integrations_schemas,
            )
            return built or None

        stack_versions = meta.get_validation_stack_versions()
        if package_integrations:
            # Combine packages per stack, but only Fleet streams that match FROM indices
            # (parity with remote prepare_mappings / get_filtered_index_schema).
            combined_by_stack: dict[str, dict[str, Any]] = {}
            ecs_by_stack: dict[str, str] = {}
            packages_by_stack: dict[str, set[str]] = {}

            for stack_version, mapping in stack_versions.items():
                ecs_version = mapping["ecs"]
                ecs_by_stack[stack_version] = ecs_version
                cache_key = (pkg_key, indices_key, str(stack_version), str(ecs_version))
                cached_schema = _ESQL_SCHEMA_DICT_CACHE.get(cache_key)
                if cached_schema is not None:
                    combined_by_stack[stack_version] = cached_schema
                    packages_by_stack[stack_version] = {
                        normalize_dataset_package(str(p["package"])) for p in package_integrations if p.get("package")
                    }
                    continue

                parsed_stack = Version.parse(stack_version)
                patch_floor = find_latest_integration_patch_for_minor(
                    {normalize_dataset_package(str(p["package"])) for p in package_integrations if p.get("package")},
                    parsed_stack.major,
                    parsed_stack.minor,
                )
                min_stack = Version(parsed_stack.major, parsed_stack.minor, max(parsed_stack.patch, patch_floor))
                ecs_flat = ecs.flatten_multi_fields(ecs.get_schema(ecs_version, name="ecs_flat"))
                package_names = [
                    normalize_dataset_package(str(p["package"])) for p in package_integrations if p.get("package")
                ]
                schema_dict, pkgs = _schema_dict_for_from_indices(
                    from_indices,
                    ecs_flat,
                    package_integrations,
                    min_stack,
                    packages_manifest,
                    integrations_schemas,
                    index_fields,
                    include_ecs=not esql_indices_covered_by_packages(from_indices, package_names, event_datasets),
                )
                packages_by_stack.setdefault(stack_version, set()).update(pkgs)

                combined_by_stack[stack_version] = schema_dict
                _ESQL_SCHEMA_DICT_CACHE[cache_key] = schema_dict

            for stack_version, schema_dict in combined_by_stack.items():
                ecs_version = ecs_by_stack.get(stack_version, "unknown")
                pkgs = ", ".join(sorted(p for p in packages_by_stack.get(stack_version, set()) if p))
                err_trailer = (
                    "Try adding event.module or event.dataset to specify integration module\n\n"
                    f"Checked against packages [{pkgs}]; stack: {stack_version}; ecs: {ecs_version}\n"
                    f"rule: {data.name} - {data.rule_id}"
                )
                targets.append(
                    ValidationTarget(
                        query_text=self.query,
                        schema=_strict_esql_schema(schema_dict, lookups_for(str(stack_version), ecs_version)),
                        err_trailer=err_trailer,
                        min_stack_version=stack_version,
                        kind="integration",
                        integration_types=sorted(packages_by_stack.get(stack_version, set())),
                    )
                )

        if not targets:
            for stack_version, mapping in stack_versions.items():
                ecs_version = mapping["ecs"]
                cache_key = (("__stack__",), indices_key, str(stack_version), str(ecs_version))
                schema_dict = _ESQL_SCHEMA_DICT_CACHE.get(cache_key)
                if schema_dict is None:
                    raw_schema = cast("dict[str, Any]", ecs.get_schema(ecs_version))
                    ecs_types: dict[str, Any] = {}
                    for key, value in raw_schema.items():
                        if isinstance(value, dict):
                            ecs_types[str(key)] = cast("dict[str, Any]", value).get("type")
                        else:
                            ecs_types[str(key)] = value
                    if len(from_indices) <= 1:
                        schema_dict = {**ecs_types, **index_fields}
                    else:
                        # One map per index, as in _schema_dict_for_from_indices, so a
                        # subquery only sees fields for the patterns on its own FROM.
                        schema_dict = {
                            index: {**ecs_types, **collect_index_field_schemas([index])} for index in from_indices
                        }
                        schema_dict["*"] = {}
                    _ESQL_SCHEMA_DICT_CACHE[cache_key] = schema_dict
                err_trailer = f"stack: {stack_version}, ecs: {ecs_version}\nrule: {data.name} - {data.rule_id}"
                targets.append(
                    ValidationTarget(
                        query_text=self.query,
                        schema=_strict_esql_schema(schema_dict, lookups_for(str(stack_version), str(ecs_version))),
                        err_trailer=err_trailer,
                        min_stack_version=str(stack_version),
                        kind="stack",
                    )
                )

        return targets

    def validate_query_text_with_schema(  # noqa: PLR0911, PLR0912, PLR0913, PLR0917
        self,
        query_text: str,
        schema: Any,
        err_trailer: str,
        min_stack_version: str,
        beat_types: list[str] | None = None,
        integration_types: list[str] | None = None,
        tree: Any | None = None,
    ) -> tuple[Exception | None, str | None]:
        """Validate ES|QL query text with detection-rules-esql-py under Schema + ParserConfig."""
        try:
            cfg = set_esql_config(min_stack_version)
            schema_ctx = schema if isinstance(schema, esql.Schema) else esql.Schema(schema or {}, allow_missing=False)
            if tree is not None:
                # Reuse a parse from the same grammar; re-check features + schema.
                with cfg:
                    esql.verify_features(tree, min_stack_version)
                    esql.analyze(tree, schema_ctx)
                self._parsed_tree = tree
            else:
                with cfg, schema_ctx:
                    tree = esql.parse_query(query_text)
                self._parsed_tree = tree
        except esql.EsqlSyntaxError as exc:
            msg = str(exc)
            if err_trailer:
                msg = f"{msg}\n\n{err_trailer}"
            return DrEsqlSyntaxError(msg), None
        except esql.EsqlNestedQueryError as exc:
            msg = str(exc)
            if err_trailer:
                msg = f"{msg}\n\n{err_trailer}"
            return DrEsqlSemanticError(msg), None
        except esql.EsqlSchemaError as exc:
            msg = str(exc)
            if err_trailer:
                msg = f"{msg}\n\n{err_trailer}"
            return DrEsqlSchemaError(msg), None
        except esql.EsqlTypeMismatchError as exc:
            msg = str(exc)
            if err_trailer:
                msg = f"{msg}\n\n{err_trailer}"
            return EsqlTypeMismatchError(msg), None
        except esql.EsqlSemanticError as exc:
            msg = str(exc)
            if err_trailer:
                msg = f"{msg}\n\n{err_trailer}"
            return DrEsqlSemanticError(msg), None
        except Exception as exc:  # noqa: BLE001
            return exc, None
        else:
            nested_exc = self._validate_nested_queries_with_schema(
                tree,
                schema_ctx,
                err_trailer=err_trailer,
                min_stack_version=min_stack_version,
                beat_types=beat_types,
                integration_types=integration_types,
            )
            if nested_exc is not None:
                return nested_exc, None
            return None, None

    def auto_add_field(self, field_name: str, index_or_dataview: str) -> None:
        """Auto add a missing field to the custom schema (parity with KQL/EQL validators)."""
        if not field_name:
            raise ValueError("No field name found")
        field_type = ecs.get_all_flattened_schema().get(field_name)
        update_auto_generated_schema(index_or_dataview, field_name, field_type)
        # Offline plan caches schemas; rebuild after custom schema mutates.
        _ESQL_SCHEMA_DICT_CACHE.clear()

    def _remember_field_types(self, plan: list[Any]) -> None:
        """Keep the newest offline type for each field used by required_fields."""
        resolved: dict[str, str] = {}
        for target in plan:
            flat = self._flat_schema_dict(target.schema)
            for name, value in flat.items():
                if isinstance(value, str) and name not in resolved:
                    resolved[name] = value
        self._resolved_field_types = resolved

    @staticmethod
    def _unknown_field_from_error(exc: Exception) -> str | None:
        """Extract an unknown field name from an ES|QL schema error message."""
        match = re.search(r"Unknown field ['\"]([^'\"]+)['\"]", str(exc))
        return match.group(1) if match else None

    @staticmethod
    def from_index_for_field(tree: Any, field_name: str, exc: Exception) -> str | None:
        """Return the first FROM pattern of the (sub)query that references field_name.

        Prefers the reference at the error position, so a field known in one
        subquery and unknown in a sibling resolves to the sibling's index.
        """
        pos = re.search(r"line:(\d+),column:(\d+)", str(exc))
        err_pos = (int(pos.group(1)) - 1, int(pos.group(2)) - 1) if pos else None
        matches: list[tuple[str, tuple[int | None, int | None]]] = []

        def visit(node: Any, scope: str | None) -> None:
            if isinstance(node, esql.ast.EsqlQuery) and node.commands:
                first = node.commands[0]
                if isinstance(first, esql.ast.FromCommand) and first.index_patterns:
                    scope = first.index_patterns[0].split(":", 1)[-1].strip()
            elif isinstance(node, esql.ast.ColumnRef) and str(node) == field_name and scope:
                matches.append((scope, (node.line, node.column)))
            for child in node.iter_children():
                visit(child, scope)

        visit(tree, None)
        for scope, node_pos in matches:
            if node_pos == err_pos:
                return scope
        return matches[0][0] if matches else None

    def validate(  # type: ignore[reportIncompatibleMethodOverride]  # noqa: PLR0912
        self,
        data: "QueryRuleData",
        rule_meta: RuleMeta,
        max_attempts: int = 10,
    ) -> None:
        """Validate an ES|QL query with detection-rules-esql-py."""
        if rule_meta.query_schema_validation is False or rule_meta.maturity == "deprecated":
            return

        _warm_esql_offline_caches()

        # Unknown FROM / LOOKUP JOIN patterns must fail.
        from_indices = get_esql_query_indices(self.query, tree=self.ast)
        lookup_targets = get_esql_lookup_join_targets(self.query, tree=self.ast)
        event_datasets = get_esql_query_event_dataset_integrations(self.query, tree=self.ast)
        stack_versions = rule_meta.get_validation_stack_versions()
        index_versions = list(stack_versions) or [load_current_package_version()]
        for stack_version in index_versions:
            _ = validate_offline_esql_from_indices(from_indices, rule_meta, event_datasets, str(stack_version))
            if lookup_targets:
                # Do not pass query event.dataset restrictions: they describe FROM, not lookup indices.
                _ = validate_offline_esql_from_indices(lookup_targets, rule_meta, [], str(stack_version))

        # Parse once per grammar snapshot; reuse AST for schema/feature checks (M6).
        # self.ast is already parsed (for FROM indices) under the current package
        # grammar — seed the cache so the matching plan target does not re-parse.
        from esql.grammar_registry import resolve_grammar_key

        schema_index = (data.index_or_dataview or from_indices or [None])[0]
        package_grammar_key = resolve_grammar_key(load_current_package_version())

        for _ in range(max_attempts):
            plan = self.build_validation_plan(data, rule_meta)
            if not plan:
                # Still parse once for AST / unique_fields
                _ = self.ast
                break

            trees_by_grammar: dict[str, Any] = {package_grammar_key: self.ast}
            first_error: Exception | None = None
            for target in plan:
                gkey = resolve_grammar_key(target.min_stack_version)
                tree = trees_by_grammar.get(gkey)
                if tree is None:
                    cfg = set_esql_config(target.min_stack_version)
                    try:
                        with cfg, esql.Schema({}, allow_missing=True):
                            tree = esql.parse_query(target.query_text)
                    except esql.EsqlSyntaxError as exc:
                        raise DrEsqlSyntaxError(str(exc)) from exc
                    trees_by_grammar[gkey] = tree
                exc, _ = self.validate_query_text_with_schema(
                    target.query_text,
                    target.schema,
                    err_trailer=target.err_trailer,
                    min_stack_version=target.min_stack_version,
                    beat_types=target.beat_types,
                    integration_types=target.integration_types,
                    tree=tree,
                )
                if exc is not None:
                    first_error = exc
                    break

            if first_error is None:
                # Older targets parse with older grammars and replace _parsed_tree.
                # Callers of ast keep the current-package tree.
                self._parsed_tree = trees_by_grammar[package_grammar_key]
                self._remember_field_types(plan)
                break

            unknown_field = self._unknown_field_from_error(first_error)
            if isinstance(first_error, DrEsqlSchemaError) and unknown_field and RULES_CONFIG.auto_gen_schema_file:
                # Subqueries each read their own FROM; add the field to that index,
                # not to the first pattern in the query.
                target_index = (
                    None if data.index_or_dataview else self.from_index_for_field(self.ast, unknown_field, first_error)
                ) or schema_index
                if target_index:
                    self.auto_add_field(unknown_field, target_index)
                    continue

            raise first_error
        else:
            raise ValueError(f"Maximum validation attempts exceeded for {data.rule_id} - {data.name}")


def extract_error_field(source: str, exc: eql.EqlParseError | kql.KqlParseError) -> str | None:
    """Extract the field name from an EQL or KQL parse error."""
    lines = source.splitlines()
    mod = -1 if exc.line == len(lines) else 0  # type: ignore[reportUnknownMemberType]
    line = lines[exc.line + mod]  # type: ignore[reportUnknownMemberType]
    start = exc.column  # type: ignore[reportUnknownMemberType]
    stop = start + len(exc.caret.strip())  # type: ignore[reportUnknownVariableType]
    return re.sub(r"^\W+|\W+$", "", line[start:stop])  # type: ignore[reportUnknownArgumentType]

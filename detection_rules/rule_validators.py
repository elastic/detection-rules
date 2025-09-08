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
from typing import Any

import eql  # type: ignore[reportMissingTypeStubs]
import kql  # type: ignore[reportMissingTypeStubs]
from eql import ast  # type: ignore[reportMissingTypeStubs]
from eql.parser import (  # type: ignore[reportMissingTypeStubs]
    KvTree,
    LarkToEQL,
    NodeInfo,
    TypeHint,
)
from eql.parser import _parse as base_parse  # type: ignore[reportMissingTypeStubs]
from marshmallow import ValidationError
from semver import Version

from . import ecs, endgame
from .beats import get_datasets_and_modules, parse_beats_from_index
from .config import CUSTOM_RULES_DIR, load_current_package_version, parse_rules_config
from .custom_schemas import update_auto_generated_schema
from .integrations import get_integration_schema_data, load_integrations_manifests, parse_datasets
from .rule import EQLRuleData, QueryRuleData, QueryValidator, RuleMeta, TOMLRuleContents, set_eql_config
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


class KQLValidator(QueryValidator):
    """Specific fields for KQL query event types."""

    @cached_property
    def ast(self) -> kql.ast.Expression:  # type: ignore[reportIncompatibleMethod]
        return kql.parse(self.query, normalize_kql_keywords=RULES_CONFIG.normalize_kql_keywords)  # type: ignore[reportUnknownMemberType]

    @cached_property
    def unique_fields(self) -> list[str]:  # type: ignore[reportIncompatibleMethod]
        return list({str(f) for f in self.ast if isinstance(f, kql.ast.Field)})  # type: ignore[reportUnknownVariableType]

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
                    f"Checked against packages [{pkgs}]; stack: {stack_version}; ecs: {ecs_version}"
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
                err_trailer = f"stack: {stack_version}, beats: {beats_version}, ecs: {ecs_version}"
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

        return targets

    def validate(self, data: QueryRuleData, meta: RuleMeta, max_attempts: int = 10) -> None:  # type: ignore[reportIncompatibleMethod]
        """Validate the query using computed schema combinations, favoring integrations when present."""
        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            return

        if data.language == "lucene":
            return

        all_targets = self.build_validation_plan(data, meta)
        has_integration = any(t.kind == "integration" for t in all_targets)
        # Order targets: integrations first (if any), then stack; otherwise just stack
        ordered_targets = (
            [t for t in all_targets if t.kind == "integration"] + [t for t in all_targets if t.kind == "stack"]
            if has_integration
            else [t for t in all_targets if t.kind == "stack"]
        )
        for _ in range(max_attempts):
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
            if err_trailer:
                trailer_parts.append(err_trailer)
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

    def auto_add_field(self, validation_checks_error: eql.errors.EqlParseError, index_or_dataview: str) -> None:
        """Auto add a missing field to the schema."""
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
            combined_by_stack: dict[str, dict[str, Any]] = {}
            ecs_by_stack: dict[str, str] = {}
            packages_by_stack: dict[str, set[str]] = {}
            for integ in get_integration_schema_data(data, meta, packaged):
                stack_version = integ["stack_version"]
                ecs_version = integ["ecs_version"]
                package = integ["package"]
                schema = integ["schema"]
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
                    f"{context}\nChecked against packages [{pkgs}]; stack: {stack_version}; ecs: {ecs_version}"
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
                    f"stack: {stack_version}, beats: {beats_version},ecs: {ecs_version}, endgame: {endgame_version}"
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
                        schema_dict = integ["schema"]

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
                            f"stack: {stack_version}, ecs: {ecs_version}"
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
                    meta_integrations = meta.integration
                    if isinstance(meta_integrations, str):
                        meta_integrations = [meta_integrations]
                    elif meta_integrations is None:
                        meta_integrations = []

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

        return targets

    def validate(self, data: "QueryRuleData", meta: RuleMeta, max_attempts: int = 10) -> None:  # type: ignore[reportIncompatibleMethodOverride]
        """Validate an EQL query using a unified plan of schema combinations."""
        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            return

        if data.language == "lucene":
            return

        # Validate rule type configuration fields against ECS schema
        set_fields, has_invalid = self.validate_rule_type_configurations(data, meta)  # type: ignore[reportArgumentType]
        if has_invalid and set_fields:
            raise ValueError(f"Rule type configuration fields not in ECS schema: {', '.join(set_fields)}")

        all_targets = self.build_validation_plan(data, meta)
        has_integration = any(t.kind == "integration" for t in all_targets)
        # Order targets: integrations first (if any), then stack; otherwise just stack
        ordered_targets = (
            [t for t in all_targets if t.kind == "integration"] + [t for t in all_targets if t.kind == "stack"]
            if has_integration
            else [t for t in all_targets if t.kind == "stack"]
        )

        for _ in range(max_attempts):
            first_error: EQL_ERROR_TYPES | ValueError | None = None
            for t in ordered_targets:
                exc = self.validate_query_text_with_schema(
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
                self.auto_add_field(first_error, data.index_or_dataview[0])  # type: ignore[reportArgumentType]
                continue

            # Raise the enriched parse error (includes target trailer + metadata)
            raise first_error

        raise ValueError(f"Maximum validation attempts exceeded for {data.rule_id} - {data.name}")

    def validate_query_text_with_schema(  # noqa: PLR0913
        self,
        query_text: str,
        schema: ecs.KqlSchema2Eql | endgame.EndgameSchema,
        err_trailer: str,
        min_stack_version: str,
        beat_types: list[str] | None = None,
        integration_types: list[str] | None = None,
    ) -> EQL_ERROR_TYPES | ValueError | None:
        """Validate the provided EQL query text against the schema (variant of validate_query_with_schema)."""
        try:
            config = set_eql_config(min_stack_version)
            with config, schema, eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
                _ = eql.parse_query(query_text)  # type: ignore[reportUnknownMemberType]
        except eql.EqlParseError as exc:
            message = exc.error_msg
            trailer_parts: list[str] = []
            if err_trailer:
                trailer_parts.append(err_trailer)
            # If the error is an unknown field and the field was referenced as optional (prefixed with '?'),
            # treat this target as non-fatal to honor EQL optional semantics.

            field = extract_error_field(query_text, exc)
            if (
                field
                and ("Unknown field" in message or "Field not recognized" in message)
                and f"?{field}" in self.query
            ):
                return None
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

            trailer = "\n\n".join(tp for tp in trailer_parts if tp)
            return exc.__class__(
                exc.error_msg,  # type: ignore[reportUnknownArgumentType]
                exc.line,  # type: ignore[reportUnknownArgumentType]
                exc.column,  # type: ignore[reportUnknownArgumentType]
                exc.source,  # type: ignore[reportUnknownArgumentType]
                len(exc.caret.lstrip()),
                trailer=trailer,
            )
        except Exception as exc:  # noqa: BLE001
            print(err_trailer)
            return exc  # type: ignore[reportReturnType]

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


class ESQLValidator(QueryValidator):
    """Validate specific fields for ESQL query event types."""

    @cached_property
    def ast(self) -> None:  # type: ignore[reportIncompatibleMethodOverride]
        return None

    @cached_property
    def unique_fields(self) -> list[str]:  # type: ignore[reportIncompatibleMethodOverride]
        """Return a list of unique fields in the query."""
        # return empty list for ES|QL rules until ast is available (friendlier than raising error)
        return []

    def validate(self, _: "QueryRuleData", __: RuleMeta) -> None:  # type: ignore[reportIncompatibleMethodOverride]
        """Validate an ESQL query while checking TOMLRule."""
        # temporarily override to NOP until ES|QL query parsing is supported

    def validate_integration(
        self,
        _: QueryRuleData,
        __: RuleMeta,
        ___: list[dict[str, Any]],
    ) -> ValidationError | None | ValueError:
        # Disabling self.validate(data, meta)
        pass


def extract_error_field(source: str, exc: eql.EqlParseError | kql.KqlParseError) -> str | None:
    """Extract the field name from an EQL or KQL parse error."""
    lines = source.splitlines()
    mod = -1 if exc.line == len(lines) else 0  # type: ignore[reportUnknownMemberType]
    line = lines[exc.line + mod]  # type: ignore[reportUnknownMemberType]
    start = exc.column  # type: ignore[reportUnknownMemberType]
    stop = start + len(exc.caret.strip())  # type: ignore[reportUnknownVariableType]
    return re.sub(r"^\W+|\W+$", "", line[start:stop])  # type: ignore[reportUnknownArgumentType]

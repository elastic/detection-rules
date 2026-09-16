# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""AST walker base classes and metadata extraction helpers."""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Iterator

from . import ast

__all__ = (
    "Walker",
    "RecursiveWalker",
    "DepthFirstWalker",
    "ConfigurableWalker",
    "get_from_sources",
    "get_metadata_fields",
    "get_field_names",
    "get_unique_fields",
    "get_keep_columns",
    "get_stats_grouping_fields",
    "get_defined_columns",
    "is_aggregate_query",
    "has_keep",
    "get_datasets_and_modules",
    "get_event_datasets",
    "find_nested_queries",
)


@dataclass(frozen=True)
class EventDataset:
    package: str
    integration: str


class Walker:
    """Base walker dispatching on AST node class names."""

    __camelcache: dict[str, str] = {}

    def __init__(self) -> None:
        self._method_cache: dict[str, dict[type, Any]] = defaultdict(dict)
        self.node_stack: list[ast.BaseNode] = []

    @classmethod
    def camelized(cls, node_cls: type | ast.BaseNode | str) -> str:
        if isinstance(node_cls, str):
            class_name = node_cls
        else:
            if not isinstance(node_cls, type):
                node_cls = type(node_cls)
            class_name = node_cls.__name__
        if class_name not in cls.__camelcache:
            pass1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", class_name)
            pass2 = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", pass1)
            cls.__camelcache[class_name] = pass2.lower()
        return cls.__camelcache[class_name]

    def get_node_method(self, node: ast.BaseNode, prefix: str = "_walk_") -> Any:
        node_cls = type(node)
        if node_cls in self._method_cache[prefix]:
            cached = self._method_cache[prefix][node_cls]
            if cached is not None:
                return cached
        queue: deque[type] = deque([node_cls])
        method = None
        while queue:
            next_cls = queue.popleft()
            method_name = prefix + self.camelized(next_cls)
            method = getattr(self, method_name, None)
            if callable(method):
                break
            queue.extend(next_cls.__bases__)
        if not callable(method):
            method = getattr(self, prefix + "default", self._walk_default)
        self._method_cache[prefix][node_cls] = method
        return method

    def _walk_default(self, node: ast.BaseNode, *args: Any, **kwargs: Any) -> ast.BaseNode:
        return node

    def walk(self, node: ast.BaseNode, *args: Any, **kwargs: Any) -> ast.BaseNode:
        self.node_stack.append(node)
        enter = getattr(self, "_enter_" + self.camelized(node), None)
        if callable(enter):
            enter(node, *args, **kwargs)
        method = self.get_node_method(node)
        result = method(node, *args, **kwargs)
        for child in node.iter_children():
            if isinstance(child, ast.BaseNode):
                self.walk(child, *args, **kwargs)
        exit_ = getattr(self, "_exit_" + self.camelized(node), None)
        if callable(exit_):
            exit_(node, *args, **kwargs)
        self.node_stack.pop()
        return result


class RecursiveWalker(Walker):
    """Walker that fully recurses before node handler returns."""


class DepthFirstWalker(Walker):
    """Explicit depth-first walker (same as base for this AST)."""


class ConfigurableWalker(Walker):
    """Walker with optional per-node configuration hooks."""

    def __init__(self, **options: Any) -> None:
        super().__init__()
        self.options = options


# --- module-level metadata helpers ---


def _iter_commands(tree: ast.EsqlQuery) -> Iterator[ast.Command]:
    yield from tree.commands


def get_from_sources(tree: ast.EsqlQuery) -> list[str]:
    sources: list[str] = []
    for cmd in _iter_commands(tree):
        if isinstance(cmd, ast.FromCommand):
            sources.extend(cmd.sources)
    return sources


def get_metadata_fields(tree: ast.EsqlQuery) -> list[str]:
    for cmd in _iter_commands(tree):
        if isinstance(cmd, ast.FromCommand):
            return list(cmd.metadata)
    return []


def get_field_names(tree: ast.EsqlQuery, *, include_output: bool = True) -> list[str]:
    names: set[str] = set()
    for node in tree:
        if isinstance(node, ast.ColumnRef):
            names.add(str(node))
    if include_output:
        names.update(get_defined_columns(tree))
    return sorted(names)


def get_unique_fields(tree: ast.EsqlQuery) -> list[str]:
    skip_prefixes = ("Esql.", "Esql_priv.", "?")
    fields = {
        name
        for name in get_field_names(tree, include_output=False)
        if not name.startswith(skip_prefixes) and name not in {"_id", "_version", "_index"}
    }
    # PRD §5.7 — union nested KQL()/EQL() fields when hooks / optional libs allow.
    fields.update(_nested_query_field_names(tree))
    return sorted(fields)


def _nested_query_field_names(tree: ast.EsqlQuery) -> set[str]:
    """Best-effort field names from nested KQL()/EQL() payloads."""
    names: set[str] = set()
    for nested in find_nested_queries(tree):
        names.update(_fields_from_nested_payload(nested))
    return names


def _fields_from_nested_payload(nested: ast.NestedQuery) -> set[str]:
    """Extract field names from a nested payload using parse hooks or optional deps."""
    from .utils import get_config_value

    text = (nested.text or "").strip()
    if not text:
        return set()

    if nested.kind == "kql":
        hook = get_config_value("kql_parse")
        try:
            if hook is not None:
                parsed = hook(text)
            else:
                import kql  # type: ignore[import-untyped]

                parsed = kql.parse(text, normalize_kql_keywords=True)
            import kql as kql_mod  # type: ignore[import-untyped]

            return {str(n) for n in kql_mod.get_field_names(parsed)}
        except Exception:  # noqa: BLE001 — optional nested merge
            return set()

    if nested.kind == "eql":
        hook = get_config_value("eql_parse")
        try:
            if hook is not None:
                parsed = hook(text)
            else:
                import eql  # type: ignore[import-untyped]

                with eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
                    try:
                        parsed = eql.parse_query(text)
                    except eql.EqlParseError:
                        parsed = eql.parse_expression(text)
            import eql  # type: ignore[import-untyped]

            return {str(f) for f in parsed if isinstance(f, eql.ast.Field)}
        except Exception:  # noqa: BLE001
            return set()

    return set()


def get_keep_columns(tree: ast.EsqlQuery) -> list[str]:
    columns: list[str] = []
    for cmd in _iter_commands(tree):
        if isinstance(cmd, ast.KeepCommand):
            columns.extend(cmd.columns)
            columns.extend(cmd.wildcards)
    return columns


def get_stats_grouping_fields(tree: ast.EsqlQuery) -> list[str]:
    for cmd in _iter_commands(tree):
        if isinstance(cmd, ast.StatsCommand):
            return list(cmd.grouping)
    return []


def get_defined_columns(tree: ast.EsqlQuery) -> set[str]:
    defined: set[str] = set()
    for cmd in _iter_commands(tree):
        if isinstance(cmd, ast.EvalCommand):
            defined.update(a.name for a in cmd.assignments)
        elif isinstance(cmd, ast.StatsCommand):
            defined.update(a.name for a in cmd.aggregates)
            # Aliased groupings (BY b = BUCKET(...)) define new columns; raw
            # grouping refs (BY host.name) are pass-through fields that must
            # still resolve against the schema, so they are not "defined" here.
            ref_names = {ref.name for ref in cmd.grouping_refs}
            defined.update(name for name in cmd.grouping if name not in ref_names)
        elif isinstance(cmd, ast.RenameCommand):
            defined.update(new for _, new in cmd.renames)
        elif isinstance(cmd, ast.GrokCommand):
            defined.update(cmd.outputs)
        elif isinstance(cmd, ast.DissectCommand):
            defined.update(cmd.outputs)
        elif isinstance(cmd, ast.EnrichCommand):
            defined.update(cmd.outputs)
        elif isinstance(cmd, ast.CompletionCommand) and cmd.target_field:
            defined.add(cmd.target_field)
        elif isinstance(cmd, ast.AssignFieldCommand) and cmd.target:
            defined.add(cmd.target)
        elif isinstance(cmd, ast.ChangePointCommand):
            if cmd.target_type:
                defined.add(cmd.target_type)
            if cmd.target_pvalue:
                defined.add(cmd.target_pvalue)
        elif isinstance(cmd, ast.RerankCommand) and cmd.target_field:
            defined.add(cmd.target_field)
        elif isinstance(cmd, ast.GenericCommand):
            defined.update(cmd.outputs)
    return defined


def is_aggregate_query(tree: ast.EsqlQuery) -> bool:
    for cmd in _iter_commands(tree):
        if isinstance(cmd, ast.StatsCommand) and cmd.grouping:
            return True
    return False


def has_keep(tree: ast.EsqlQuery) -> bool:
    return any(isinstance(cmd, ast.KeepCommand) for cmd in _iter_commands(tree))


def _literal_strings(expr: ast.Expression | None) -> list[str]:
    if expr is None:
        return []
    if isinstance(expr, ast.Literal) and isinstance(expr.value, str):
        return [expr.value]
    if isinstance(expr, ast.BinaryExpr):
        return _literal_strings(expr.left) + _literal_strings(expr.right)
    if isinstance(expr, ast.FunctionCall):
        if expr.name == "__values__":
            values: list[str] = []
            for arg in expr.args:
                values.extend(_literal_strings(arg))
            return values
        values = []
        for arg in expr.args:
            values.extend(_literal_strings(arg))
        return values
    return []


def get_datasets_and_modules(tree: ast.EsqlQuery) -> tuple[set[str], set[str]]:
    datasets: set[str] = set()
    modules: set[str] = set()
    for node in tree:
        if isinstance(node, ast.BinaryExpr) and node.op in {"==", "in"}:
            left = node.left
            if isinstance(left, ast.ColumnRef):
                if left.name == "event.dataset":
                    datasets.update(_literal_strings(node.right))
                elif left.name == "data_stream.dataset":
                    datasets.update(_literal_strings(node.right))
                elif left.name == "event.module":
                    modules.update(_literal_strings(node.right))
    return datasets, modules


def get_event_datasets(tree: ast.EsqlQuery) -> list[EventDataset]:
    datasets, _ = get_datasets_and_modules(tree)
    result: list[EventDataset] = []
    for dataset in sorted(datasets):
        if "." in dataset:
            package, integration = dataset.split(".", 1)
            result.append(EventDataset(package=package, integration=integration))
    return result


def find_nested_queries(tree: ast.EsqlQuery) -> list[ast.NestedQuery]:
    """Return nested KQL/EQL payloads only (subquery/PROMQL remain opaque)."""
    nested: list[ast.NestedQuery] = []
    for node in tree:
        if isinstance(node, ast.NestedQuery) and node.kind in {"kql", "eql"}:
            nested.append(node)
    return nested

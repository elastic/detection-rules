# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Semantic analysis: schema validation, column tracking, and type checks.

When `Schema(allow_missing=False)` is active, expression types are checked for
arithmetic, comparisons (`==` / ordering), `IN`, and string predicates
(`LIKE` / `RLIKE` / `MATCH`).
"""

from __future__ import annotations

from . import ast
from .errors import EsqlSchemaError, EsqlSemanticError, EsqlTypeMismatchError
from .functions import get_signature
from .schema import Schema
from .types import (
    comparison_family,
    elasticsearch_type_family,
    is_time_duration_literal,
    types_comparable,
    types_date_math,
    types_numeric,
    types_orderable,
)
from .walkers import get_defined_columns

__all__ = ("analyze", "infer_column_types")

_SKIP_FIELDS = frozenset({"_id", "_version", "_index", "_source", "_ignored", "_score"})
_SKIP_PREFIXES = ("Esql.", "Esql_priv.", "?")
_ARITH_OPS = frozenset({"+", "-", "*", "/", "%"})
_EQ_OPS = frozenset({"==", "!=", "is", "is not"})
_ORDER_OPS = frozenset({"<", "<=", ">", ">="})
_IN_OPS = frozenset({"in", "not_in"})
_STRING_PREDICATES = frozenset({"like", "rlike", "match"})
_BOOL_OPS = frozenset({"and", "or"})
_BOOLEAN_GROUPS = frozenset({"boolean"})

# Fallback return types when no signature.return_type / inherit applies.
_FUNC_RETURN_TYPES: dict[str, str] = {
    "count": "long",
    "count_distinct": "long",
    "sum": "double",
    "avg": "double",
    "median": "double",
    "percentile": "double",
    "to_long": "long",
    "to_integer": "integer",
    "to_double": "double",
    "to_unsigned_long": "unsigned_long",
    "to_boolean": "boolean",
    "length": "integer",
    "mv_count": "integer",
    "concat": "keyword",
    "left": "keyword",
    "right": "keyword",
    "substring": "keyword",
    "to_string": "keyword",
    "now": "date",
}


def analyze(tree: ast.EsqlQuery, schema: Schema) -> None:
    """Validate column references, command shape, and schema-aware type checks."""
    defined = get_defined_columns(tree)
    column_types = infer_column_types(tree, schema)
    for name, line, column in _iter_field_refs(tree):
        if name in _SKIP_FIELDS or name in defined:
            continue
        if any(name.startswith(prefix) for prefix in _SKIP_PREFIXES):
            continue
        if "*" in name:
            # Wildcard projections (e.g. KEEP aws.*) are not resolved offline.
            continue
        if not schema.has_field(name) and not schema.allow_missing:
            raise EsqlSchemaError(
                f"Unknown field {name!r}",
                line=line or 0,
                column=column or 0,
                source=name,
            )

    if schema.allow_missing:
        return

    _check_commands(tree, schema, defined)
    _check_expression_types(tree, schema, column_types)


def infer_column_types(tree: ast.EsqlQuery, schema: Schema) -> dict[str, str]:
    """Infer types for schema fields and pipeline-defined columns (EVAL/STATS/…)."""
    env: dict[str, str] = {}
    for name in _SKIP_FIELDS:
        env[name] = "keyword"
    for field_name, field_type in getattr(schema, "_fields", {}).items():
        # Keep raw ES types (ip/boolean) so comparison_family can distinguish them.
        env[field_name] = field_type if isinstance(field_type, str) else elasticsearch_type_family(field_type)

    for cmd in tree.commands:
        if isinstance(cmd, ast.EvalCommand):
            for alias in cmd.assignments:
                env[alias.name] = _expr_type(alias.expr, schema, env) or "unknown"
        elif isinstance(cmd, ast.StatsCommand):
            next_env: dict[str, str] = {}
            alias_names = {alias.name for alias in cmd.grouping_aliases}
            for alias in cmd.grouping_aliases:
                next_env[alias.name] = _expr_type(alias.expr, schema, env) or "unknown"
            for group in cmd.grouping:
                if group in alias_names:
                    continue
                next_env[group] = env.get(group) or _schema_field_type(schema, group) or "unknown"
            for alias in cmd.aggregates:
                next_env[alias.name] = _expr_type(alias.expr, schema, env) or "unknown"
            env = next_env
        elif isinstance(cmd, ast.RenameCommand):
            for old, new in cmd.renames:
                env[new] = env.pop(old, env.get(old, "unknown"))
        elif isinstance(cmd, (ast.GrokCommand, ast.DissectCommand, ast.EnrichCommand)):
            for name in cmd.outputs:
                env.setdefault(name, "keyword")
        elif isinstance(cmd, ast.CompletionCommand) and cmd.target_field:
            env[cmd.target_field] = "keyword"
        elif isinstance(cmd, ast.AssignFieldCommand) and cmd.target:
            env[cmd.target] = "keyword"
        elif isinstance(cmd, ast.ChangePointCommand):
            if cmd.target_type:
                env[cmd.target_type] = "keyword"
            if cmd.target_pvalue:
                env[cmd.target_pvalue] = "double"
        elif isinstance(cmd, ast.RerankCommand) and cmd.target_field:
            env[cmd.target_field] = "double"
        elif isinstance(cmd, ast.GenericCommand):
            for name in cmd.outputs:
                env.setdefault(name, "keyword")
    return env


def _schema_field_type(schema: Schema, name: str) -> str | None:
    return schema.resolve_field(name)


def _iter_field_refs(tree: ast.EsqlQuery) -> list[tuple[str, int | None, int | None]]:
    """Yield field names from ColumnRef nodes and KEEP/DROP column lists."""
    refs: list[tuple[str, int | None, int | None]] = []
    for node in tree:
        if isinstance(node, ast.ColumnRef):
            refs.append((str(node), node.line, node.column))
        elif isinstance(node, ast.KeepCommand):
            for name in node.columns:
                refs.append((name, node.line, node.column))
        elif isinstance(node, ast.DropCommand):
            for name in node.columns:
                refs.append((name, node.line, node.column))
    return refs


def _check_commands(tree: ast.EsqlQuery, schema: Schema, defined: set[str]) -> None:
    for cmd in tree.commands:
        if isinstance(cmd, ast.GenericCommand) and cmd.name in {"", "unknown"}:
            raise EsqlSemanticError(
                f"Unsupported or unrecognized command {cmd.name!r}",
                line=cmd.line or 0,
                column=cmd.column or 0,
                source=cmd.name,
            )
        if isinstance(cmd, ast.EnrichCommand) and cmd.match_field:
            _require_known_field(cmd.match_field, schema, defined, cmd.line, cmd.column)
        if isinstance(cmd, ast.JoinCommand):
            for field in cmd.on_fields:
                if field and all(ch.isalnum() or ch in "._" for ch in field):
                    _require_known_field(field, schema, defined, cmd.line, cmd.column)


def _require_known_field(
    name: str,
    schema: Schema,
    defined: set[str],
    line: int | None,
    column: int | None,
) -> None:
    if name in _SKIP_FIELDS or name in defined or "*" in name:
        return
    if any(name.startswith(prefix) for prefix in _SKIP_PREFIXES):
        return
    if not schema.has_field(name):
        raise EsqlSchemaError(
            f"Unknown field {name!r}",
            line=line or 0,
            column=column or 0,
            source=name,
        )


def _check_expression_types(
    tree: ast.EsqlQuery,
    schema: Schema,
    column_types: dict[str, str],
) -> None:
    """Expression type checks against the schema type environment."""
    for cmd in tree.commands:
        if isinstance(cmd, ast.WhereCommand) and cmd.predicate is not None:
            _require_boolean_context(cmd.predicate, schema, column_types, "WHERE")

    for node in tree:
        if isinstance(node, ast.BinaryExpr):
            op = str(node.op).strip().lower()
            if op in _BOOL_OPS:
                _require_boolean_context(node.left, schema, column_types, op.upper())
                _require_boolean_context(node.right, schema, column_types, op.upper())
            _check_binary_expr(node, schema, column_types)
        elif isinstance(node, ast.FunctionCall):
            fname = node.name.lower()
            if fname == "not" and node.args:
                _require_boolean_context(node.args[0], schema, column_types, "NOT")
            if fname in _STRING_PREDICATES:
                _check_string_predicate(node, schema, column_types)
            _check_function_signature(node, schema, column_types)


def _require_boolean_context(
    expr: ast.Expression,
    schema: Schema,
    column_types: dict[str, str],
    context: str,
) -> None:
    expr_type = _expr_type(expr, schema, column_types)
    if expr_type is None or expr_type == "unknown":
        return
    if comparison_family(expr_type) not in _BOOLEAN_GROUPS:
        raise EsqlTypeMismatchError(
            f"Expected boolean expression in {context}, got {comparison_family(expr_type)!r}",
            line=expr.line or 0,
            column=expr.column or 0,
            source=context,
        )


def _check_function_signature(
    node: ast.FunctionCall,
    schema: Schema,
    column_types: dict[str, str],
) -> None:
    fname = node.name.lower()
    if fname in {"__values__", "is_null", "is_not_null", "not"} or fname in _STRING_PREDICATES:
        return
    sig = get_signature(fname)
    if sig is None:
        return
    argc = len(node.args)
    if argc < sig.min_args:
        raise EsqlTypeMismatchError(
            f"Function {fname.upper()}() expects at least {sig.min_args} argument(s), got {argc}",
            line=node.line or 0,
            column=node.column or 0,
            source=fname,
        )
    if sig.max_args is not None and argc > sig.max_args:
        raise EsqlTypeMismatchError(
            f"Function {fname.upper()}() expects at most {sig.max_args} argument(s), got {argc}",
            line=node.line or 0,
            column=node.column or 0,
            source=fname,
        )
    if not sig.arg_groups:
        return
    for index, arg in enumerate(node.args):
        group_index = min(index, len(sig.arg_groups) - 1)
        allowed = sig.arg_groups[group_index]
        arg_type = _expr_type(arg, schema, column_types)
        if arg_type is None or arg_type == "unknown":
            continue
        group = comparison_family(arg_type)
        if group == "unknown":
            continue
        if group not in allowed and "unknown" not in allowed:
            raise EsqlTypeMismatchError(
                f"Function {fname.upper()}() argument {index + 1} has type {group!r}, "
                f"expected one of {sorted(allowed)}",
                line=arg.line or node.line or 0,
                column=arg.column or node.column or 0,
                source=fname,
            )


def _check_binary_expr(
    node: ast.BinaryExpr,
    schema: Schema,
    column_types: dict[str, str],
) -> None:
    op = str(node.op).strip().lower()
    left_type = _expr_type(node.left, schema, column_types)
    right_type = _expr_type(node.right, schema, column_types)

    if op in _ARITH_OPS:
        if left_type is None or right_type is None or left_type == "unknown" or right_type == "unknown":
            return
        if (types_numeric(left_type) and types_numeric(right_type)) or types_date_math(left_type, right_type):
            return
        raise EsqlTypeMismatchError(
            f"Cannot apply arithmetic operator {op!r} to types "
            f"{comparison_family(left_type)!r} and {comparison_family(right_type)!r}",
            line=node.line or 0,
            column=node.column or 0,
            source=op,
        )

    if op in _IN_OPS:
        _check_in_expr(node, left_type, schema, column_types)
        return

    if op in _EQ_OPS:
        if not types_comparable(left_type, right_type):
            raise EsqlTypeMismatchError(
                f"Cannot compare types {comparison_family(left_type)!r} and "
                f"{comparison_family(right_type)!r} with {op!r}",
                line=node.line or 0,
                column=node.column or 0,
                source=op,
            )
        return

    if op in _ORDER_OPS:
        if not types_orderable(left_type, right_type):
            raise EsqlTypeMismatchError(
                f"Cannot order types {comparison_family(left_type)!r} and "
                f"{comparison_family(right_type)!r} with {op!r}",
                line=node.line or 0,
                column=node.column or 0,
                source=op,
            )


def _check_in_expr(
    node: ast.BinaryExpr,
    left_type: str | None,
    schema: Schema,
    column_types: dict[str, str],
) -> None:
    right = node.right
    # IN (subquery) — NestedQuery is opaque; BinaryExpr still yields boolean.
    if isinstance(right, ast.NestedQuery):
        return
    values: list[ast.Expression] = []
    if isinstance(right, ast.FunctionCall) and right.name == "__values__":
        values = list(right.args)
    elif isinstance(right, ast.Expression):
        values = [right]
    for value in values:
        value_type = _expr_type(value, schema, column_types)
        if not types_comparable(left_type, value_type):
            raise EsqlTypeMismatchError(
                f"Cannot compare types {comparison_family(left_type)!r} and "
                f"{comparison_family(value_type)!r} with 'in'",
                line=node.line or 0,
                column=node.column or 0,
                source="in",
            )


def _check_string_predicate(
    node: ast.FunctionCall,
    schema: Schema,
    column_types: dict[str, str],
) -> None:
    if not node.args:
        return
    left_type = _expr_type(node.args[0], schema, column_types)
    if left_type is None or left_type == "unknown":
        return
    group = comparison_family(left_type)
    if group not in {"string", "date"}:
        raise EsqlTypeMismatchError(
            f"Cannot apply {node.name.upper()}() to type {group!r}",
            line=node.line or 0,
            column=node.column or 0,
            source=node.name,
        )


def _expr_type(
    expr: ast.Expression,
    schema: Schema,
    column_types: dict[str, str],
) -> str | None:
    if isinstance(expr, ast.ColumnRef):
        name = str(expr)
        if name in column_types:
            return column_types[name]
        if name in _SKIP_FIELDS:
            return "keyword"
        return schema.resolve_field(name)
    if isinstance(expr, ast.Literal):
        kind = (expr.kind or "").lower()
        # bool is a subclass of int — check boolean before numeric.
        if kind == "boolean" or isinstance(expr.value, bool):
            return "boolean"
        if kind in {"integer", "long", "number"} or isinstance(expr.value, int):
            return "long"
        if kind in {"double", "float", "decimal"} or isinstance(expr.value, float):
            return "double"
        if isinstance(expr.value, str) or kind == "string":
            if is_time_duration_literal(expr.value, kind):
                return "time_duration"
            return "keyword"
        if expr.value is None or kind == "null":
            return "unknown"
        return "unknown"
    if isinstance(expr, ast.FunctionCall):
        fname = expr.name.lower()
        if fname in {"is_null", "is_not_null", "not"}:
            return "boolean"
        if fname in _STRING_PREDICATES:
            return "boolean"
        sig = get_signature(fname)
        if sig is not None:
            if sig.return_type == "inherit" and expr.args:
                return _expr_type(expr.args[0], schema, column_types) or "unknown"
            if sig.return_type != "unknown":
                return sig.return_type
        if fname in _FUNC_RETURN_TYPES:
            return _FUNC_RETURN_TYPES[fname]
        if fname in {"min", "max"} and expr.args:
            return _expr_type(expr.args[0], schema, column_types) or "double"
        return "unknown"
    if isinstance(expr, ast.BinaryExpr):
        op = str(expr.op).strip().lower()
        if op in _ARITH_OPS:
            left = _expr_type(expr.left, schema, column_types)
            right = _expr_type(expr.right, schema, column_types)
            if left and right and types_numeric(left) and types_numeric(right):
                left_f = elasticsearch_type_family(left)
                right_f = elasticsearch_type_family(right)
                return "double" if "double" in {left_f, right_f} else "long"
            return None
        if op in _EQ_OPS | _ORDER_OPS | _IN_OPS or op in {"and", "or"}:
            return "boolean"
        return "unknown"
    if isinstance(expr, ast.Alias):
        return _expr_type(expr.expr, schema, column_types)
    # NestedQuery alone is not a boolean predicate (IN subquery wraps it in BinaryExpr).
    if isinstance(expr, ast.NestedQuery):
        return "object"
    return None

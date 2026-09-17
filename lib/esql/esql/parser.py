# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""ES|QL parser entry points."""

from __future__ import annotations

from typing import Any, Callable

from antlr4 import CommonTokenStream, InputStream
from antlr4.error.ErrorListener import ErrorListener

from . import ast
from .analyzer import analyze, check_catalog_names
from .ast_builder import build_ast
from .errors import EsqlNestedQueryError, EsqlSyntaxError
from .grammar_registry import build_esql_config, get_grammar_module
from .schema import Schema
from .utils import get_config_value
from .verifier import verify_features
from .walkers import find_nested_queries

__all__ = ("parse_query", "parse_expression", "validate_nested_queries")


class _EsqlErrorListener(ErrorListener):
    def __init__(self, source: str) -> None:
        self.source = source
        self.source_lines = source.splitlines() or [""]

    def syntaxError(
        self,
        recognizer: Any,
        offendingSymbol: Any,
        line: int,
        column: int,
        msg: str,
        e: Any,
    ) -> None:
        source_line = self.source_lines[line - 1] if 0 < line <= len(self.source_lines) else ""
        width = 1
        if offendingSymbol is not None and hasattr(offendingSymbol, "text") and offendingSymbol.text:
            width = len(offendingSymbol.text)
        raise EsqlSyntaxError(msg, line - 1, column, source_line, width=width)


def _parse_with_grammar(
    text: str,
    *,
    rule: str | None = None,
    min_stack_version: str | None = None,
) -> Any:
    module = get_grammar_module(min_stack_version or get_config_value("min_stack_version"))
    lexer = module.lexer_cls(InputStream(text))
    config = build_esql_config(get_current_parser_context())
    lexer.removeErrorListeners()
    listener = _EsqlErrorListener(text)
    lexer.addErrorListener(listener)
    lexer.setEsqlConfig(config)

    stream = CommonTokenStream(lexer)
    parser = module.parser_cls(stream)
    parser.removeErrorListeners()
    parser.addErrorListener(listener)
    parser.setEsqlConfig(config)

    if rule is None:
        # Prefer statements (SET preamble + query) when the grammar has it (9.3+).
        # 8.19 only exposes singleStatement.
        rule = "statements" if hasattr(parser, "statements") else "singleStatement"
    method = getattr(parser, rule)
    return method()


def get_current_parser_context() -> dict[str, Any]:
    """Merge thread-local ParserConfig values relevant to ANTLR."""
    keys = (
        "dev_version",
        "external_data_sources",
        "min_stack_version",
        "features",
        "schema",
        "kql_parse",
        "eql_parse",
    )
    ctx: dict[str, Any] = {}
    for key in keys:
        value = get_config_value(key)
        if value is not None:
            ctx[key] = value
    return ctx


def parse_query(text: str) -> ast.EsqlQuery:
    """Parse a full ES|QL piped query into an AST."""
    tree = _parse_with_grammar(text)
    result = build_ast(tree)
    verify_features(result, get_config_value("min_stack_version"))
    schema = get_config_value("schema")
    if isinstance(schema, Schema):
        # Always analyze under a Schema: allow_missing only relaxes index-field
        # lookups; KEEP/DROP/STATS column visibility still applies. Function
        # name/arity still run when a real ES catalog exists for this stack.
        analyze(result, schema)
    else:
        check_catalog_names(result)
    validate_nested_queries(result)
    return result


def parse_expression(text: str) -> ast.Expression:
    """Parse a standalone ES|QL expression."""
    wrapped = f"ROW x = {text}"
    query = parse_query(wrapped)
    for cmd in query.commands:
        if isinstance(cmd, ast.RowCommand) and cmd.fields:
            return cmd.fields[0].expr
    raise EsqlSyntaxError("Unable to parse expression", 0, 0, text)


def validate_nested_queries(tree: ast.EsqlQuery) -> None:
    """Validate nested KQL/EQL payloads using hooks from ParserConfig context."""
    kql_parse: Callable[[str], Any] | None = get_config_value("kql_parse")
    eql_parse: Callable[[str], Any] | None = get_config_value("eql_parse")
    for nested in find_nested_queries(tree):
        hook = kql_parse if nested.kind == "kql" else eql_parse
        if hook is None:
            continue
        try:
            hook(nested.text)
        except Exception as exc:  # noqa: BLE001 — surface nested parser failures
            raise EsqlNestedQueryError(
                f"Invalid nested {nested.kind.upper()} query",
                kind=nested.kind,
                inner=exc,
                line=nested.line or nested.locus.line or 0,
                column=nested.column or nested.locus.column or 0,
                source=nested.text[:80],
            ) from exc


def render(tree: ast.EsqlQuery) -> str:
    """Render a best-effort ES|QL string from an AST (lossy for complex expressions)."""
    parts: list[str] = []
    for cmd in tree.commands:
        if isinstance(cmd, ast.FromCommand):
            rendered_sources: list[str] = []
            for src in cmd.sources:
                if isinstance(src, str):
                    rendered_sources.append(src)
                else:
                    rendered_sources.append(f"({render(src)})")
            chunk = "FROM " + ", ".join(rendered_sources)
            if cmd.metadata:
                chunk += " METADATA " + ", ".join(cmd.metadata)
            parts.append(chunk)
        elif isinstance(cmd, ast.WhereCommand):
            parts.append("WHERE /* predicate */")
        elif isinstance(cmd, ast.KeepCommand):
            cols = cmd.columns + cmd.wildcards
            parts.append("KEEP " + ", ".join(cols))
        elif isinstance(cmd, ast.StatsCommand):
            aggs = ", ".join(a.name for a in cmd.aggregates)
            chunk = "STATS " + aggs if aggs else "STATS"
            if cmd.grouping:
                chunk += " BY " + ", ".join(cmd.grouping)
            parts.append(chunk)
        elif isinstance(cmd, ast.GenericCommand):
            parts.append(cmd.name.upper() + (" " + cmd.text if cmd.text else ""))
        else:
            parts.append(type(cmd).__name__.replace("Command", "").upper())
    return " | ".join(parts)

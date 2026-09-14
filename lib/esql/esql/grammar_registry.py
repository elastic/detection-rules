# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Map stack versions to generated ANTLR grammar modules."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import Any

from .release_window import (
    default_module,
    grammar_snapshots,
    tip_module,
)
from .versions import Version

__all__ = (
    "GrammarModule",
    "get_grammar_module",
    "resolve_grammar_key",
    "GRAMMAR_SNAPSHOTS",
    "DEFAULT_MODULE",
    "TIP_MODULE",
    "build_esql_config",
)

# Derived from esql.release_window — do not edit lists here.
DEFAULT_MODULE = default_module()
TIP_MODULE = tip_module()
GRAMMAR_SNAPSHOTS: list[tuple[Version, str]] = grammar_snapshots()


@dataclass(frozen=True)
class GrammarModule:
    version_key: str
    lexer_cls: type
    parser_cls: type
    visitor_cls: type


_MODULE_CACHE: dict[str, GrammarModule] = {}


def _load_module(key: str) -> GrammarModule:
    import_module(f"esql._antlr.{key}")
    lexer_mod = import_module(f"esql._antlr.{key}.EsqlBaseLexer")
    parser_mod = import_module(f"esql._antlr.{key}.EsqlBaseParser")
    visitor_mod = import_module(f"esql._antlr.{key}.EsqlBaseParserVisitor")
    return GrammarModule(
        version_key=key,
        lexer_cls=lexer_mod.EsqlBaseLexer,
        parser_cls=parser_mod.EsqlBaseParser,
        visitor_cls=visitor_mod.EsqlBaseParserVisitor,
    )


def resolve_grammar_key(min_stack_version: str | Version | None = None) -> str:
    """Return ANTLR module key for a stack version."""
    if min_stack_version is None:
        return DEFAULT_MODULE
    text = str(min_stack_version).strip().lower()
    if text in {"latest", "main", "master"}:
        return TIP_MODULE

    version = Version.parse(min_stack_version)
    newest_floor = GRAMMAR_SNAPSHOTS[-1][0]
    # Beyond the newest numbered release-window line → main tip
    if (version.major, version.minor) > (newest_floor.major, newest_floor.minor):
        return TIP_MODULE

    chosen = GRAMMAR_SNAPSHOTS[0][1]
    for floor, key in GRAMMAR_SNAPSHOTS:
        if version >= floor:
            chosen = key
    return chosen


def get_grammar_module(min_stack_version: str | Version | None = None) -> GrammarModule:
    """Select the ANTLR module for a stack version (newest snapshot <= version)."""
    key = resolve_grammar_key(min_stack_version)
    if key not in _MODULE_CACHE:
        _MODULE_CACHE[key] = _load_module(key)
    return _MODULE_CACHE[key]


def build_esql_config(context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build the dict passed to lexer/parser `setEsqlConfig`."""
    ctx = dict(context or {})
    return {
        "dev_version": bool(ctx.get("dev_version", False)),
        "external_data_sources": bool(ctx.get("external_data_sources", False)),
    }

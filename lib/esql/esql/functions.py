# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""ES|QL function and command registries from Elasticsearch kibana/generated.

Signatures are code-generated into `esql/_generated/<module>.zip`. That tree is
ES-published editor metadata (same git refs as grammar), not a Kibana runtime
dependency.

Stacks whose ES ref has no `kibana/generated` tree get a **missing** marker —
they do not inherit another stack's map. Hand overrides apply only on top of a
real catalog.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from . import functions_overrides as _overrides
from .generated_store import read_json_member
from .grammar_registry import DEFAULT_MODULE, resolve_grammar_key

__all__ = (
    "FUNCTIONS",
    "NESTED_QUERY_FUNCTIONS",
    "FunctionSignature",
    "get_signature",
    "has_command_catalog",
    "has_function_catalog",
    "is_known_command",
    "is_known_function",
)


@dataclass(frozen=True)
class FunctionSignature:
    """Function signature for offline arity and argument-type checks."""

    name: str
    min_args: int
    max_args: int | None  # None = unbounded (variadic)
    arg_groups: tuple[frozenset[str], ...]  # per-position; last repeats when variadic
    return_type: str  # ES-ish type, "boolean", "unknown", or "inherit"


# Commands with typed AST nodes. kibana/generated `commands.json` is an editor
# list and omits some grammar commands (FROM, FUSE, SHOW, …).
_TYPED_COMMAND_NAMES: frozenset[str] = frozenset(
    {
        "from",
        "ts",
        "row",
        "set",
        "show",
        "promql",
        "explain",
        "external",
        "where",
        "keep",
        "drop",
        "eval",
        "stats",
        "inline_stats",
        "sort",
        "limit",
        "rename",
        "grok",
        "dissect",
        "enrich",
        "mv_expand",
        "join",
        "lookup",
        "lookup_join",
        "fork",
        "completion",
        "sample",
        "change_point",
        "rerank",
        "fuse",
        "highlight",
        "mmr",
        "metrics_info",
        "ts_info",
        "ts_collapse",
        "dedup",
        "user_agent",
        "uri_parts",
        "ip_location",
        "registered_domain",
    }
)


def _decode_signature(name: str, payload: dict[str, Any]) -> FunctionSignature:
    groups_raw = payload.get("arg_groups") or []
    arg_groups = tuple(frozenset(group) for group in groups_raw)
    max_args = payload.get("max_args")
    return FunctionSignature(
        name=name,
        min_args=int(payload.get("min_args", 0)),
        max_args=None if max_args is None else int(max_args),
        arg_groups=arg_groups,
        return_type=str(payload.get("return_type", "unknown")),
    )


def _read_signatures_file(module: str) -> dict[str, Any] | None:
    raw = read_json_member(module, "function_signatures.json")
    if raw is None or not isinstance(raw, dict):
        return None
    return raw


def _is_catalog_payload(raw: dict[str, Any]) -> bool:
    return any(isinstance(value, dict) and "min_args" in value for value in raw.values())


def _is_missing_marker(raw: dict[str, Any]) -> bool:
    """True when this module has no stack-true catalog (do not follow another stack)."""
    if raw.get("status") == "missing":
        return True
    # Legacy fallback pointers (pre-stack-true catalogs) are treated as missing.
    if "fallback_module" in raw and not _is_catalog_payload(raw):
        return True
    return False


def _catalog_entries(raw: dict[str, Any]) -> dict[str, Any]:
    return {str(name).lower(): value for name, value in raw.items() if isinstance(value, dict) and "min_args" in value}


@lru_cache(maxsize=16)
def _module_has_catalog(module: str) -> bool:
    raw = _read_signatures_file(module)
    return raw is not None and _is_catalog_payload(raw) and not _is_missing_marker(raw)


@lru_cache(maxsize=16)
def _load_module_signatures(module: str) -> dict[str, FunctionSignature]:
    """Load generated signatures for *module*. No cross-stack fallback."""
    if not _module_has_catalog(module):
        return {}
    raw = _read_signatures_file(module)
    if raw is None:
        return {}
    payload = _catalog_entries(raw)
    signatures: dict[str, FunctionSignature] = {name: _decode_signature(name, value) for name, value in payload.items()}
    for name, spec in _overrides.SIGNATURE_OVERRIDE_SPECS.items():
        signatures[name] = _decode_signature(name, spec)
    return signatures


@lru_cache(maxsize=16)
def _load_module_commands(module: str) -> frozenset[str] | None:
    """Known command names for *module*, or None when there is no command catalog."""
    if not _module_has_catalog(module):
        return None
    raw = read_json_member(module, "commands.json")
    if not isinstance(raw, list):
        return None
    return frozenset(str(name).lower() for name in raw)


def _module_for_stack(stack: str | None) -> str:
    if stack is not None:
        return resolve_grammar_key(stack)
    from .utils import get_config_value

    return resolve_grammar_key(get_config_value("min_stack_version"))


def has_function_catalog(stack: str | None = None) -> bool:
    """Return True when this stack has a real ES function catalog (not a missing marker)."""
    return _module_has_catalog(_module_for_stack(stack))


def has_command_catalog(stack: str | None = None) -> bool:
    """Return True when this stack has a real ES command-name catalog."""
    return _load_module_commands(_module_for_stack(stack)) is not None


def _canonical_function_name(name: str) -> str:
    lowered = name.lower()
    return _overrides.FUNCTION_ALIASES.get(lowered, lowered)


def get_signature(name: str, stack: str | None = None) -> FunctionSignature | None:
    """Return the signature for *name*, optionally for a specific stack version."""
    module = _module_for_stack(stack)
    return _load_module_signatures(module).get(_canonical_function_name(name))


def is_known_function(name: str, stack: str | None = None) -> bool:
    if not has_function_catalog(stack):
        return False
    module = _module_for_stack(stack)
    names = set(_load_module_signatures(module))
    names |= set(_overrides.NESTED_QUERY_FUNCTION_NAMES)
    names |= set(_overrides.FUNCTION_ALIASES)
    return _canonical_function_name(name) in names or name.lower() in names


def is_known_command(name: str, stack: str | None = None) -> bool:
    """Return True when *name* is a typed AST command or listed in the stack catalog.

    With no command catalog, returns True (do not invent a denylist).
    """
    lowered = name.lower()
    if lowered in _TYPED_COMMAND_NAMES:
        return True
    commands = _load_module_commands(_module_for_stack(stack))
    if commands is None:
        return True
    return lowered in commands


def _default_known_names() -> frozenset[str]:
    names = set(_load_module_signatures(DEFAULT_MODULE))
    names |= set(_overrides.NESTED_QUERY_FUNCTION_NAMES)
    names |= set(_overrides.FUNCTION_ALIASES)
    return frozenset(names)


# Public constants — DEFAULT stack line (newest numbered floor).
# Populated after generate-definitions; empty until then (tests/CI require generate).
FUNCTIONS: frozenset[str] = frozenset()
NESTED_QUERY_FUNCTIONS: frozenset[str] = _overrides.NESTED_QUERY_FUNCTION_NAMES


def _refresh_public_constants() -> None:
    """Recompute `FUNCTIONS` after generated files appear (import-time + tests)."""
    global FUNCTIONS
    FUNCTIONS = _default_known_names()


_refresh_public_constants()

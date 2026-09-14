# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""ES|QL function registry: names, return types, and argument signatures.

Signatures are code-generated from Elasticsearch `kibana/generated` definitions
into `esql/_generated/<module>.zip` (`function_signatures.json` member). Hand
overrides live in `esql.functions_overrides` and always win.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from . import functions_overrides as _overrides
from .generated_store import read_json_member
from .grammar_registry import DEFAULT_MODULE, TIP_MODULE, resolve_grammar_key

__all__ = (
    "FUNCTIONS",
    "NESTED_QUERY_FUNCTIONS",
    "FunctionSignature",
    "get_signature",
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


def _is_fallback_pointer(raw: dict[str, Any]) -> bool:
    if "fallback_module" not in raw:
        return False
    return not any(isinstance(value, dict) and "min_args" in value for value in raw.values())


def _resolve_module_payload(module: str) -> dict[str, Any]:
    """Return signatures dict for *module*, following fallback_module pointers."""
    visited: set[str] = set()
    current = module
    while current not in visited:
        visited.add(current)
        raw = _read_signatures_file(current)
        if raw is None:
            return {}
        if _is_fallback_pointer(raw):
            fallback = raw.get("fallback_module")
            if not isinstance(fallback, str) or not fallback:
                return {}
            current = fallback
            continue
        return {
            str(name).lower(): value for name, value in raw.items() if isinstance(value, dict) and "min_args" in value
        }
    return {}


@lru_cache(maxsize=16)
def _load_module_signatures(module: str) -> dict[str, FunctionSignature]:
    """Load generated signatures for *module*, applying overrides."""
    payload = _resolve_module_payload(module)
    if not payload:
        for fallback in (DEFAULT_MODULE, TIP_MODULE):
            if fallback == module:
                continue
            payload = _resolve_module_payload(fallback)
            if payload:
                break

    signatures: dict[str, FunctionSignature] = {name: _decode_signature(name, value) for name, value in payload.items()}
    for name, spec in _overrides.SIGNATURE_OVERRIDE_SPECS.items():
        signatures[name] = _decode_signature(name, spec)
    return signatures


def _module_for_stack(stack: str | None) -> str:
    if stack is not None:
        return resolve_grammar_key(stack)
    from .utils import get_config_value

    return resolve_grammar_key(get_config_value("min_stack_version"))


def get_signature(name: str, stack: str | None = None) -> FunctionSignature | None:
    """Return the signature for *name*, optionally for a specific stack version."""
    module = _module_for_stack(stack)
    return _load_module_signatures(module).get(name.lower())


def is_known_function(name: str, stack: str | None = None) -> bool:
    module = _module_for_stack(stack)
    names = set(_load_module_signatures(module))
    names |= set(_overrides.EXTRA_KNOWN_FUNCTIONS)
    names |= set(_overrides.NESTED_QUERY_FUNCTION_NAMES)
    return name.lower() in names


def _default_known_names() -> frozenset[str]:
    names = set(_load_module_signatures(DEFAULT_MODULE))
    names |= set(_overrides.EXTRA_KNOWN_FUNCTIONS)
    names |= set(_overrides.NESTED_QUERY_FUNCTION_NAMES)
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

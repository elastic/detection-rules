# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Elasticsearch field type normalization and comparison families."""

from __future__ import annotations

import re
from typing import Any

__all__ = (
    "elasticsearch_type_family",
    "normalize_type",
    "comparison_family",
    "types_comparable",
    "types_orderable",
    "types_numeric",
    "types_date_math",
    "is_time_duration_literal",
)

_KEYWORD_FAMILY = frozenset(
    {
        "keyword",
        "constant_keyword",
        "wildcard",
        "match_only_text",
        "version",
        "ip",
        "boolean",
    }
)
_TEXT_FAMILY = frozenset({"text", "match_only_text", "search_as_you_type"})
_LONG_FAMILY = frozenset({"long", "integer", "short", "byte", "unsigned_long"})
_DOUBLE_FAMILY = frozenset({"double", "float", "half_float", "scaled_float"})
_DATE_FAMILY = frozenset({"date", "date_nanos"})
_OBJECT_FAMILY = frozenset({"object", "flattened", "nested", "pass_through"})
_STRING_COMPARE = frozenset(
    {
        "keyword",
        "constant_keyword",
        "wildcard",
        "match_only_text",
        "version",
        "text",
        "search_as_you_type",
        "ip",
        "string",
    }
)


def normalize_type(es_type: str | dict[str, Any] | None) -> str | None:
    """Normalize an ES mapping type to a lowercase string."""
    if es_type is None:
        return None
    if isinstance(es_type, dict):
        if "type" in es_type:
            return str(es_type["type"]).lower()
        if "properties" in es_type:
            return "object"
        return "object"
    return str(es_type).lower()


def elasticsearch_type_family(es_type: str | dict[str, Any] | None) -> str:
    """Map Elasticsearch types to coarse families used by validation."""
    normalized = normalize_type(es_type)
    if normalized is None:
        return "unknown"
    if normalized in _KEYWORD_FAMILY:
        return "keyword"
    if normalized in _TEXT_FAMILY:
        return "text"
    if normalized in _LONG_FAMILY:
        return "long"
    if normalized in _DOUBLE_FAMILY:
        return "double"
    if normalized in _DATE_FAMILY:
        return "date"
    if normalized in _OBJECT_FAMILY:
        return "object"
    if normalized == "binary":
        return "binary"
    return normalized


def comparison_family(es_type: str | dict[str, Any] | None) -> str:
    """Map a type to a comparison family: string/number/boolean/date/…"""
    normalized = normalize_type(es_type)
    if normalized is None:
        return "unknown"
    # Preserve boolean separately (unlike elasticsearch_type_family).
    if normalized == "boolean":
        return "boolean"
    if normalized in {"time_duration", "date_period"}:
        return "time_duration"
    if normalized in _STRING_COMPARE:
        return "string"
    if normalized in _LONG_FAMILY or normalized in _DOUBLE_FAMILY or normalized in {"long", "double", "number"}:
        return "number"
    if normalized in _DATE_FAMILY or normalized == "date":
        return "date"
    if normalized in _OBJECT_FAMILY or normalized == "object":
        return "object"
    if normalized == "binary":
        return "binary"
    if normalized == "unknown":
        return "unknown"
    # Already-collapsed families from infer_column_types
    if normalized == "keyword" or normalized == "text":
        return "string"
    return normalized


def types_numeric(es_type: str | dict[str, Any] | None) -> bool:
    """Return True when the type may participate in arithmetic."""
    family = elasticsearch_type_family(es_type)
    return family in {"long", "double", "date"}


def types_comparable(left: str | None, right: str | None) -> bool:
    """Return True when *left* and *right* may be compared with == / != / IN.

    Compatible pairs:
    - number ↔ number (long/double)
    - string ↔ string (keyword/text/ip)
    - date ↔ date, and date ↔ string (ISO date literals)
    - boolean ↔ boolean, and boolean ↔ string (`== "true"` patterns)
    - unknown is permissive (skip)
    """
    if left is None or right is None:
        return True
    left_g = comparison_family(left)
    right_g = comparison_family(right)
    if left_g == "unknown" or right_g == "unknown":
        return True
    if normalize_type(left) in {"object", "nested"} or normalize_type(right) in {"object", "nested"}:
        return False
    if left_g == right_g:
        return True
    # Date literals are often strings in ES|QL.
    if {left_g, right_g} <= {"date", "string"}:
        return True
    # Integration schemas type some flags as boolean while rules compare to "true".
    if {left_g, right_g} <= {"boolean", "string"}:
        return True
    return False


def types_orderable(left: str | None, right: str | None) -> bool:
    """Return True when *left* and *right* may use < / <= / > / >=."""
    if left is None or right is None:
        return True
    left_g = comparison_family(left)
    right_g = comparison_family(right)
    if left_g == "unknown" or right_g == "unknown":
        return True
    if left_g == "number" and right_g == "number":
        return True
    if left_g == "string" and right_g == "string":
        return True
    if {left_g, right_g} <= {"date", "string"}:
        return True
    return False


_DURATION_RE = re.compile(r"\d+(?:ms|micros|nanos|[smhdw])")


def is_time_duration_literal(value: object, kind: str | None = None) -> bool:
    """Return True for ES|QL time-duration tokens like `5m`, `1d`."""
    if not isinstance(value, str):
        return False
    text = value.strip().lower().replace(" ", "")
    return bool(text and _DURATION_RE.fullmatch(text))


def types_date_math(left: str | None, right: str | None) -> bool:
    """Return True when date arithmetic `date ± duration` is allowed."""
    left_g = comparison_family(left) if left else "unknown"
    right_g = comparison_family(right) if right else "unknown"
    if left_g == "date" and right_g in {"time_duration", "string", "number", "date"}:
        return True
    if right_g == "date" and left_g in {"time_duration", "string", "number", "date"}:
        return True
    return False

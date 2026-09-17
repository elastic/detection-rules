# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Schema resolution for ES|QL field validation."""

from __future__ import annotations

import fnmatch
import re
from typing import Any

from .errors import EsqlError
from .types import normalize_type
from .utils import ParserConfig

__all__ = ("Schema",)

_IDENT_RE = re.compile(r"^[_a-zA-Z][a-zA-Z0-9_.]*$")
_METADATA_FIELDS = frozenset({"_id", "_version", "_index", "_source", "_ignored", "_score"})


class Schema(ParserConfig):
    """Field schema for semantic validation.

    Accepts:
    - flat `{field: type}` mapping
    - nested Elasticsearch `{properties: ...}` mapping
    - multi-index `{pattern: mapping}` — patterns are **unioned** (or filtered
      by `index_pattern` when provided)

    ``lookups`` is a separate map of LOOKUP JOIN target index → field schema.
    Those fields are not on the primary index; the analyzer adds them only
    after the matching ``LOOKUP JOIN``.
    """

    def __init__(
        self,
        mapping: dict[str, Any],
        *,
        allow_missing: bool = False,
        index_pattern: str | None = None,
        lookups: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self.allow_missing = allow_missing
        self.index_pattern = index_pattern
        self._fields = self._flatten_mapping(mapping, index_pattern=index_pattern)
        self._lookups: dict[str, dict[str, str]] = {
            name: self._flatten_mapping(nested) for name, nested in (lookups or {}).items()
        }
        super().__init__(schema=self)

    def lookup_fields(self, index_name: str | None) -> dict[str, str]:
        """Return the field schema for a LOOKUP JOIN target, or empty."""
        if not index_name:
            return {}
        name = index_name.strip("`")
        if name in self._lookups:
            return self._lookups[name]
        matched: dict[str, str] = {}
        for pattern, fields in self._lookups.items():
            if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(pattern, name):
                matched.update(fields)
        return matched

    @staticmethod
    def _flatten_mapping(
        mapping: Any,
        prefix: str = "",
        *,
        index_pattern: str | None = None,
    ) -> dict[str, str]:
        if not isinstance(mapping, dict):
            return {}

        # Multi-index: values look like nested mappings keyed by index pattern.
        if prefix == "" and mapping and all(isinstance(v, dict) for v in mapping.values()):
            if not any(k in mapping for k in ("properties", "type")):
                # Heuristic: pattern-like keys, or every value shaped like an index
                # mapping (bare index names carry no ``*``/``.``).
                if any("*" in k or "." in k for k in mapping) or all("properties" in v for v in mapping.values()):
                    fields: dict[str, str] = {}
                    for pattern, nested in mapping.items():
                        if index_pattern is not None and not (
                            fnmatch.fnmatch(index_pattern, pattern) or fnmatch.fnmatch(pattern, index_pattern)
                        ):
                            continue
                        fields.update(Schema._flatten_mapping(nested, prefix))
                    return fields

        fields = {}

        if "properties" in mapping:
            for name, spec in mapping["properties"].items():
                path = f"{prefix}.{name}" if prefix else name
                Schema._flatten_field_spec(path, spec, fields)
            return fields

        for name, spec in mapping.items():
            if name.startswith("_") and name not in _METADATA_FIELDS:
                continue
            path = f"{prefix}.{name}" if prefix else name
            if isinstance(spec, str):
                fields[path] = spec.lower()
            else:
                Schema._flatten_field_spec(path, spec, fields)
        return fields

    @staticmethod
    def _flatten_field_spec(path: str, spec: Any, fields: dict[str, str]) -> None:
        """Register *path* (and any sub-fields) from a field spec dict."""
        if not isinstance(spec, dict):
            fields[path] = spec.lower() if isinstance(spec, str) else "unknown"
            return
        has_children = isinstance(spec.get("properties"), dict) or isinstance(spec.get("fields"), dict)
        # A parent with an explicit type is itself a field (e.g. keyword with a
        # .text multi-field); a pure object container (properties only) is not.
        if "type" in spec or not has_children:
            fields[path] = normalize_type(spec) or "unknown"
        for container in ("properties", "fields"):
            children = spec.get(container)
            if isinstance(children, dict):
                for name, child in children.items():
                    Schema._flatten_field_spec(f"{path}.{name}", child, fields)

    def resolve_field(self, name: str) -> str | None:
        """Resolve a dotted field name to its type, or None if unknown."""
        if name in _METADATA_FIELDS:
            return "keyword"
        if name.startswith("Esql.") or name.startswith("Esql_priv.") or name.startswith("?"):
            return "unknown"
        if name in self._fields:
            return self._fields[name]
        # Wildcard / suffix patterns are not resolved offline.
        return None

    def has_field(self, name: str) -> bool:
        return self.resolve_field(name) is not None

    def validate(self) -> None:
        for name in self._fields:
            if not _IDENT_RE.match(name.replace(".", "_").replace("*", "x")):
                raise EsqlError(f"Invalid field name in schema: {name!r}")

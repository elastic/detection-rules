# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Detection-rule ES|QL shape validation (KEEP / METADATA / STATS)."""

from __future__ import annotations

from . import ast
from .errors import EsqlSemanticError
from .walkers import get_keep_columns, get_metadata_fields, has_keep, is_aggregate_query

__all__ = ("validate_detection_rule_query",)

_REQUIRED_METADATA = frozenset({"_id", "_version", "_index"})


def validate_detection_rule_query(tree: ast.EsqlQuery, name: str = "") -> None:
    """Validate ES|QL queries used in detection-rules packaging.

    Mirrors `ESQLRuleData.validates_esql_data` regex checks using the AST.
    """
    label = f"Rule: {name}" if name else "Rule"

    if not is_aggregate_query(tree):
        metadata = set(get_metadata_fields(tree))
        if not _REQUIRED_METADATA.issubset(metadata):
            raise EsqlSemanticError(
                f"{label} contains a non-aggregate query without metadata fields "
                f"'_id', '_version', and '_index' -> Add 'metadata _id, _version, _index' "
                f"to the from command or add an aggregate function."
            )

    if not has_keep(tree):
        raise EsqlSemanticError(f"{label} does not contain a 'keep' command -> Add a 'keep' command to the query.")

    if not is_aggregate_query(tree):
        keep_columns = {c.strip() for c in get_keep_columns(tree)}
        if "*" not in keep_columns and not _REQUIRED_METADATA.issubset(keep_columns):
            raise EsqlSemanticError(
                f"{label} contains a keep clause without metadata fields "
                f"'_id', '_version', and '_index' -> Add '_id', '_version', '_index' to the keep command."
            )

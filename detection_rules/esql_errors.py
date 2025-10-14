# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""ESQL exceptions."""

from collections.abc import Sequence

from elasticsearch import Elasticsearch  # type: ignore[reportMissingTypeStubs]

from .misc import ClientError, getdefault

__all__ = (
    "EsqlKibanaBaseError",
    "EsqlSchemaError",
    "EsqlSemanticError",
    "EsqlSyntaxError",
    "EsqlTypeMismatchError",
    "EsqlUnknownIndexError",
    "EsqlUnsupportedTypeError",
)


def cleanup_empty_indices(
    elastic_client: Elasticsearch, index_patterns: Sequence[str] = ("rule-test-*", "test-*")
) -> None:
    """Delete empty indices matching the given patterns."""
    if getdefault("skip_empty_index_cleanup")():
        return
    for pattern in index_patterns:
        indices = elastic_client.cat.indices(index=pattern, format="json")
        empty_indices = [index["index"] for index in indices if index["docs.count"] == "0"]  # type: ignore[reportMissingTypeStubs]
        for empty_index in empty_indices:
            _ = elastic_client.indices.delete(index=empty_index)


class EsqlKibanaBaseError(ClientError):
    """Base class for ESQL exceptions with cleanup logic."""

    def __init__(
        self,
        message: str,
        elastic_client: Elasticsearch,
    ) -> None:
        cleanup_empty_indices(elastic_client)
        super().__init__(message, original_error=self)


class EsqlSchemaError(EsqlKibanaBaseError):
    """Error in ESQL schema. Validated via Kibana until AST is available."""


class EsqlUnsupportedTypeError(EsqlKibanaBaseError):
    """Error in ESQL type validation using unsupported type."""


class EsqlSyntaxError(EsqlKibanaBaseError):
    """Error with ESQL syntax."""


class EsqlTypeMismatchError(ClientError):
    """Error when validating types in ESQL. Can occur in stack or local schema comparison."""

    def __init__(
        self,
        message: str,
        elastic_client: Elasticsearch | None = None,
    ) -> None:
        if elastic_client:
            cleanup_empty_indices(elastic_client)
        super().__init__(message, original_error=self)


class EsqlSemanticError(ClientError):
    """Error with ESQL semantics. Validated through regex enforcement."""

    def __init__(self, message: str) -> None:
        super().__init__(message, original_error=self)


class EsqlUnknownIndexError(ClientError):
    """Error with ESQL Indices. Validated through regex enforcement."""

    def __init__(self, message: str) -> None:
        super().__init__(message, original_error=self)


ESQL_EXCEPTION_TYPES = (
    EsqlSchemaError,
    EsqlSyntaxError,
    EsqlUnsupportedTypeError,
    EsqlTypeMismatchError,
    EsqlKibanaBaseError,
    EsqlSemanticError,
    EsqlUnknownIndexError,
)

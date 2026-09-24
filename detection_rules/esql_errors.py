# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""ESQL exceptions."""

from .misc import ClientError

__all__ = (
    "EsqlKibanaBaseError",
    "EsqlSchemaError",
    "EsqlSemanticError",
    "EsqlSyntaxError",
    "EsqlTypeMismatchError",
    "EsqlUnknownIndexError",
    "EsqlUnsupportedTypeError",
)


class EsqlKibanaBaseError(ClientError):
    """Base class for offline ES|QL validation errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message, original_error=self)


class EsqlSchemaError(EsqlKibanaBaseError):
    """Error in an ES|QL schema check."""


class EsqlUnsupportedTypeError(EsqlKibanaBaseError):
    """Error in ES|QL type validation using an unsupported type."""


class EsqlSyntaxError(EsqlKibanaBaseError):
    """Error with ES|QL syntax."""


class EsqlTypeMismatchError(ClientError):
    """Error when an ES|QL expression compares incompatible types."""

    def __init__(self, message: str) -> None:
        super().__init__(message, original_error=self)


class EsqlSemanticError(ClientError):
    """Error with ES|QL semantics."""

    def __init__(self, message: str) -> None:
        super().__init__(message, original_error=self)


class EsqlUnknownIndexError(ClientError):
    """Error when an ES|QL FROM or LOOKUP JOIN pattern is unknown."""

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

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
    """Base class for ESQL exceptions."""

    def __init__(self, message: str) -> None:
        super().__init__(message, original_error=self)


class EsqlSchemaError(EsqlKibanaBaseError):
    """Error in ESQL schema."""


class EsqlUnsupportedTypeError(EsqlKibanaBaseError):
    """Error in ESQL type validation using unsupported type."""


class EsqlSyntaxError(EsqlKibanaBaseError):
    """Error with ESQL syntax."""


class EsqlTypeMismatchError(ClientError):
    """Error when validating types in ESQL. Can occur in stack or local schema comparison."""

    def __init__(self, message: str) -> None:
        super().__init__(message, original_error=self)


class EsqlSemanticError(ClientError):
    """Error with ESQL semantics."""

    def __init__(self, message: str) -> None:
        super().__init__(message, original_error=self)


class EsqlUnknownIndexError(ClientError):
    """Error with ESQL indices."""

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

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""ES|QL exceptions."""

from __future__ import annotations

import re

__all__ = (
    "EsqlError",
    "EsqlSyntaxError",
    "EsqlSemanticError",
    "EsqlSchemaError",
    "EsqlTypeMismatchError",
    "EsqlUnsupportedTypeError",
    "EsqlVersionError",
    "EsqlNestedQueryError",
)


class EsqlError(Exception):
    """Base class for ES|QL errors."""


class _EsqlLocatedError(EsqlError):
    """Error with optional source location and caret formatting."""

    template = "Error at line:{},column:{}\n{}\n{}\n{}"

    def __init__(
        self,
        error_msg: str,
        line: int = 0,
        column: int = 0,
        source: str = "",
        width: int = 1,
        trailer: str | None = None,
    ) -> None:
        self.error_msg = error_msg
        self.line = line
        self.column = column
        self.source = source
        self.trailer = trailer
        leading = re.sub(r"[^\t]", " ", source)[:column]
        self.caret = leading + ("^" * max(width, 1))
        message = self.template.format(line + 1, column + 1, error_msg, source, self.caret)
        if trailer:
            message += "\n" + trailer
        super().__init__(message)


class EsqlSyntaxError(_EsqlLocatedError):
    """Error with ES|QL syntax."""


class EsqlSemanticError(_EsqlLocatedError):
    """Error with ES|QL semantics."""


class EsqlSchemaError(EsqlSemanticError):
    """Error for missing or invalid schema fields."""


class EsqlTypeMismatchError(EsqlSemanticError):
    """Error when validating types."""


class EsqlUnsupportedTypeError(EsqlSemanticError):
    """Error for unsupported Elasticsearch field types."""


class EsqlVersionError(EsqlSemanticError):
    """Error when a feature is unavailable for the target stack version."""


class EsqlNestedQueryError(EsqlSemanticError):
    """Wraps failures from nested KQL/EQL validation with outer locus."""

    def __init__(
        self,
        error_msg: str,
        *,
        kind: str,
        inner: Exception | None = None,
        line: int = 0,
        column: int = 0,
        source: str = "",
        width: int = 1,
        trailer: str | None = None,
    ) -> None:
        self.kind = kind
        self.inner = inner
        if inner is not None and trailer is None:
            trailer = f"Nested {kind} error: {inner}"
        super().__init__(error_msg, line, column, source, width, trailer)

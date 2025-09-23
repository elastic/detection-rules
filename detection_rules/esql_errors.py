"""ESQL exceptions."""

from marshmallow.exceptions import ValidationError

__all__ = (
    "EsqlSchemaError",
    "EsqlSemanticError",
    "EsqlSyntaxError",
    "EsqlTypeMismatchError",
)


class EsqlSchemaError(ValidationError):
    """Error for missing fields in ESQL."""


class EsqlSyntaxError(ValidationError):
    """Error with ESQL syntax."""

    # TODO: Update this to a Kibana Error extension? Perhaps?


class EsqlSemanticError(ValidationError):
    """Error with ESQL semantics."""

    # TODO: Update this to a Kibana Error extension? Perhaps?


class EsqlTypeMismatchError(ValidationError):
    """Error when validating types in ESQL."""

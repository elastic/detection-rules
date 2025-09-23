"""ESQL exceptions."""

__all__ = (
    "EsqlSchemaError",
    "EsqlSemanticError",
    "EsqlSyntaxError",
    "EsqlTypeMismatchError",
)


class EsqlSchemaError(Exception):
    """Error in ESQL schema. Validated via Kibana until AST is available."""

    def __init__(self, message: str):
        super().__init__(message)


class EsqlSyntaxError(Exception):
    """Error with ESQL syntax. Validated via Kibana until AST is available."""

    def __init__(self, message: str):
        super().__init__(message)


class EsqlSemanticError(Exception):
    """Error with ESQL semantics. Validated via Kibana until AST is available."""

    def __init__(self, message: str):
        super().__init__(message)


class EsqlTypeMismatchError(Exception):
    """Error when validating types in ESQL."""

    def __init__(self, message: str):
        super().__init__(message)

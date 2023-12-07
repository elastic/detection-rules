# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Custom error handling for ESQL."""
from antlr4.error.ErrorListener import ErrorListener


class ESQLSyntaxError(Exception):
    """Exception raised for syntax errors of an ESQL query."""

    def __init__(self, message):
        """Initialize the custom syntax ESQL exception."""
        message = f"ESQL syntax error: {message}"
        super().__init__(message)
        print(message)


class ESQLSemanticError(Exception):
    """Exception raised for semantic errors of an ESQL query."""

    def __init__(self, message):
        """Initialize the custom semantic ESQL exception."""
        message = f"ESQL semantic error: {message}"
        super().__init__(message)
        print(message)


class ESQLErrorListener(ErrorListener):
    """Custom error listener for ESQL."""
    def __init__(self):
        """Initialize the custom error listener."""
        super().__init__()
        self.errors = []

    def syntaxError(self, recognizer, offendingSymbol, line, column, msg, e):  # noqa: N802,N803
        """Handle syntax errors."""
        self.errors.append(f"Line {line}:{column} {msg}")

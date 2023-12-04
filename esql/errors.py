# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.
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

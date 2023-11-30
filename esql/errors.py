# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

class ESQLSyntaxError(Exception):
    """Exception raised for syntax/semantic errors of an ESQL query."""

    def __init__(self, message):
        """Initialize the custom ESQL exception."""
        super().__init__(message)

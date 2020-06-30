# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

from eql import EqlError, EqlParseError, EqlCompileError


class KqlParseError(EqlParseError):
    """EQL Parsing Error."""


class KqlCompileError(EqlCompileError):
    """Class for KQL-specific compile errors."""


class KqlRuntimeError(EqlError):
    """Error for failures within the KQL evaluator."""

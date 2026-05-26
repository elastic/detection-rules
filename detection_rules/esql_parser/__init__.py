# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Python wrapper around the Elasticsearch Java ES|QL parser & verifier.

Spawns the JVM-based daemon in ``lib/esql-validator`` and exchanges
line-delimited JSON over stdin/stdout to validate arbitrary ES|QL queries.
"""

from .validator import EsqlValidator, ValidationError, ValidationResult

__all__ = ("EsqlValidator", "ValidationError", "ValidationResult")

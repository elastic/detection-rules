# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Definitions for rule metadata and schemas."""

from .v7_11 import ApiSchema711


class ApiSchema712(ApiSchema711):
    """Schema for siem rule in API format."""

    STACK_VERSION = "7.12"

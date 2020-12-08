# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Definitions for rule metadata and schemas."""

import jsl
from .v7_9 import ApiSchema79


class ApiSchema710(ApiSchema79):
    """Schema for siem rule in API format."""

    STACK_VERSION = "7.10"
    RULE_TYPES = ApiSchema79.RULE_TYPES + [EQL]

    type = jsl.StringField(enum=RULE_TYPES, required=True)

    # there might be a bug in jsl that requires us to redefine these here
    query_scope = ApiSchema79.query_scope
    saved_id_scope = ApiSchema79.saved_id_scope
    ml_scope = ApiSchema79.ml_scope
    threshold_scope = ApiSchema79.threshold_scope

    with jsl.Scope(EQL) as eql_scope:
        eql_scope.index = jsl.ArrayField(jsl.StringField(), required=False)
        eql_scope.query = jsl.StringField(required=True)
        eql_scope.language = jsl.StringField(enum=[EQL], required=True, default=EQL)
        eql_scope.type = jsl.StringField(enum=[EQL], required=True)

    with jsl.Scope(jsl.DEFAULT_ROLE) as default_scope:
        default_scope.type = type

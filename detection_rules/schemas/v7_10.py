# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Definitions for rule metadata and schemas."""

import jsl
from .v7_9 import ApiSchema79


# rule types
EQL = "eql"
THREAT_MATCH = "threat_match"


class ApiSchema710(ApiSchema79):
    """Schema for siem rule in API format."""

    class ThreatMatchEntries(jsl.Document):
        """Threat match rule entries."""

        class ThreatMatchEntry(jsl.Document):
            """Threat match rule mapping entry."""

            field = jsl.StringField(required=True)
            type = jsl.StringField(default='mapping', enum='mapping', required=True)
            value = jsl.StringField(required=True)

        entries = jsl.ArrayField(jsl.DocumentField(ThreatMatchEntry, required=True), min_items=1)

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

    with jsl.Scope(THREAT_MATCH) as tm_scope:
        tm_scope.type = jsl.StringField(enum=THREAT_MATCH, required=True)
        tm_scope.language = jsl.StringField(enum=['kuery', 'lucene'], required=True, default=EQL)
        tm_scope.index = jsl.ArrayField(jsl.StringField(), required=False)
        tm_scope.query = jsl.StringField(required=True)
        tm_scope.threat_query = jsl.StringField(default='*:*', required=True)
        tm_scope.threat_mapping = jsl.ArrayField(jsl.DocumentField(ThreatMatchEntries, required=True), min_items=1)
        tm_scope.threat_language = jsl.StringField(enum=['kuery', 'lucene'], required=True, default=EQL)
        tm_scope.threat_index = jsl.ArrayField(jsl.StringField(required=True), min_items=1)

        # API items not defined here
        #   filters: filtersOrUndefined,
        #   savedId: savedIdOrUndefined,
        #   threatFilters: filtersOrUndefined,
        #   concurrentSearches: concurrentSearchesOrUndefined,
        #   itemsPerSearch: itemsPerSearchOrUndefined,

    with jsl.Scope(jsl.DEFAULT_ROLE) as default_scope:
        default_scope.type = type

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Definitions for rule metadata and schemas."""

import jsl
from .v78 import ApiSchema78


OPERATORS = ['equals']


# kibana/.../siem/server/lib/detection_engine/routes/schemas/add_prepackaged_rules_schema.ts
#                           /detection_engine/routes/schemas/schemas.ts
# rule_id is required here
# output_index is not allowed (and instead the space index must be used)
# immutable defaults to true instead of to false and if it is there can only be true
# enabled defaults to false instead of true
# version is a required field that must exist

# rule types
THRESHOLD = "threshold"


class RiskScoreMapping(jsl.Document):
    field = jsl.StringField(required=True)
    operator = jsl.StringField(required=False, enum=OPERATORS)
    value = jsl.StringField(required=False)


class SeverityMapping(jsl.Document):
    field = jsl.StringField(required=True)
    operator = jsl.StringField(required=False, enum=OPERATORS)
    value = jsl.StringField(required=False)
    severity = jsl.StringField(required=False)


class ThresholdMapping(jsl.Document):
    field = jsl.StringField(required=False)
    value = jsl.IntField(minimum=1, required=True)


class ApiSchema79(ApiSchema78):
    """Schema for siem rule in API format."""

    STACK_VERSION = "7.9"
    RULE_TYPES = ApiSchema78.RULE_TYPES + [THRESHOLD]

    author = jsl.ArrayField(jsl.StringField(default="Elastic"), required=True, min_items=1)
    building_block_type = jsl.StringField(required=False)
    exceptions_list = jsl.ArrayField(required=False)
    license = jsl.StringField(required=True, default="Elastic License")
    risk_score_mapping = jsl.ArrayField(jsl.DocumentField(RiskScoreMapping), required=False, min_items=1)
    rule_name_override = jsl.StringField(required=False)
    severity_mapping = jsl.ArrayField(jsl.DocumentField(SeverityMapping), required=False, min_items=1)
    timestamp_override = jsl.StringField(required=False)

    type = jsl.StringField(enum=RULE_TYPES, required=True)

    # there might be a bug in jsl that requires us to redefine these here
    query_scope = ApiSchema78.query_scope
    saved_id_scope = ApiSchema78.saved_id_scope
    ml_scope = ApiSchema78.ml_scope

    with jsl.Scope(THRESHOLD) as threshold_scope:
        threshold_scope.index = jsl.ArrayField(jsl.StringField(), required=False)
        # this is not required per the API but we will enforce it here
        threshold_scope.language = jsl.StringField(enum=['kuery', 'lucene'], required=True, default='kuery')
        threshold_scope.query = jsl.StringField(required=True)
        threshold_scope.type = jsl.StringField(enum=[THRESHOLD], required=True, default=THRESHOLD)
        threshold_scope.threshold = jsl.DocumentField(ThresholdMapping, required=True)

    with jsl.Scope(jsl.DEFAULT_ROLE) as default_scope:
        default_scope.type = type

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Definitions for rule metadata and schemas."""

import jsl

from .base import BaseApiSchema, MarkdownField
from .definitions import INTERVAL_PATTERN, MITRE_URL_PATTERN, MACHINE_LEARNING, SAVED_QUERY, QUERY
from ..attack import tactics, tactics_map, technique_id_list


# kibana/.../siem/server/lib/detection_engine/routes/schemas/add_prepackaged_rules_schema.ts
#                           /detection_engine/routes/schemas/schemas.ts
# rule_id is required here
# output_index is not allowed (and instead the space index must be used)
# immutable defaults to true instead of to false and if it is there can only be true
# enabled defaults to false instead of true
# version is a required field that must exist

# rule types


class Filters(jsl.Document):
    """Intermediate schema for handling DSL-like filters."""

    class FilterMetadata(jsl.Document):
        negate = jsl.BooleanField()
        type = jsl.StringField()
        key = jsl.StringField()
        value = jsl.StringField()
        disabled = jsl.BooleanField()
        indexRefName = jsl.StringField()
        alias = jsl.StringField()  # null acceptable
        params = jsl.DictField(properties={'query': jsl.StringField()})

    class FilterQuery(jsl.Document):
        match = jsl.DictField({
            'event.action': jsl.DictField(properties={
                'query': jsl.StringField(),
                'type': jsl.StringField()
            })
        })

    class FilterState(jsl.Document):
        store = jsl.StringField()

    class FilterExists(jsl.Document):
        field = jsl.StringField()

    exists = jsl.DocumentField(FilterExists)
    meta = jsl.DocumentField(FilterMetadata)
    state = jsl.DocumentField(FilterState, name='$state')
    query = jsl.DictField()


class Threat(jsl.Document):
    """Threat framework mapping such as MITRE ATT&CK."""

    class ThreatTactic(jsl.Document):
        id = jsl.StringField(enum=tactics_map.values(), required=True)
        name = jsl.StringField(enum=tactics, required=True)
        reference = jsl.StringField(MITRE_URL_PATTERN.format(type='tactics'))

    class ThreatTechnique(jsl.Document):
        id = jsl.StringField(enum=technique_id_list, required=True)
        name = jsl.StringField(required=True)
        reference = jsl.StringField(MITRE_URL_PATTERN.format(type='techniques'), required=True)

    framework = jsl.StringField(default='MITRE ATT&CK', required=True)
    tactic = jsl.DocumentField(ThreatTactic, required=True)
    technique = jsl.ArrayField(jsl.DocumentField(ThreatTechnique), required=True)


class ApiSchema78(BaseApiSchema):
    """Schema for siem rule in API format."""

    STACK_VERSION = "7.8"
    RULE_TYPES = [MACHINE_LEARNING, SAVED_QUERY, QUERY]

    actions = jsl.ArrayField(required=False)
    description = jsl.StringField(required=True)
    # api defaults to false if blank
    enabled = jsl.BooleanField(default=False, required=False)
    # _ required since `from` is a reserved word in python
    from_ = jsl.StringField(required=False, default='now-6m', name='from')
    false_positives = jsl.ArrayField(jsl.StringField(), required=False)
    filters = jsl.ArrayField(jsl.DocumentField(Filters))
    interval = jsl.StringField(pattern=INTERVAL_PATTERN, default='5m', required=False)
    max_signals = jsl.IntField(minimum=1, required=False, default=100)  # cap a max?
    meta = jsl.DictField(required=False)
    name = jsl.StringField(required=True)
    note = MarkdownField(required=False)
    # output_index =jsl.StringField(required=False)  # this is NOT allowed!
    references = jsl.ArrayField(jsl.StringField(), required=False)
    risk_score = jsl.IntField(minimum=0, maximum=100, required=True, default=21)
    severity = jsl.StringField(enum=['low', 'medium', 'high', 'critical'], default='low', required=True)
    tags = jsl.ArrayField(jsl.StringField(), required=False)
    throttle = jsl.StringField(required=False)
    timeline_id = jsl.StringField(required=False)
    timeline_title = jsl.StringField(required=False)
    to = jsl.StringField(required=False, default='now')

    type = jsl.StringField(enum=[MACHINE_LEARNING, QUERY, SAVED_QUERY], required=True)
    threat = jsl.ArrayField(jsl.DocumentField(Threat), required=False, min_items=1)

    with jsl.Scope(MACHINE_LEARNING) as ml_scope:
        ml_scope.anomaly_threshold = jsl.IntField(required=True, minimum=0)
        ml_scope.machine_learning_job_id = jsl.StringField(required=True)
        ml_scope.type = jsl.StringField(enum=[MACHINE_LEARNING], required=True, default=MACHINE_LEARNING)

    with jsl.Scope(SAVED_QUERY) as saved_id_scope:
        saved_id_scope.index = jsl.ArrayField(jsl.StringField(), required=False)
        saved_id_scope.saved_id = jsl.StringField(required=True)
        saved_id_scope.type = jsl.StringField(enum=[SAVED_QUERY], required=True, default=SAVED_QUERY)

    with jsl.Scope(QUERY) as query_scope:
        query_scope.index = jsl.ArrayField(jsl.StringField(), required=False)
        # this is not required per the API but we will enforce it here
        query_scope.language = jsl.StringField(enum=['kuery', 'lucene'], required=True, default='kuery')
        query_scope.query = jsl.StringField(required=True)
        query_scope.type = jsl.StringField(enum=[QUERY], required=True, default=QUERY)

    with jsl.Scope(jsl.DEFAULT_ROLE) as default_scope:
        default_scope.type = type

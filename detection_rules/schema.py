# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Definitions for rule metadata and schemas."""
import time

import jsl
import jsonschema

from . import ecs
from .attack import TACTICS, TACTICS_MAP, TECHNIQUES, technique_lookup
from .utils import cached

UUID_PATTERN = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
DATE_PATTERN = r'\d{4}/\d{2}/\d{2}'
VERSION_PATTERN = r'\d+\.\d+\.\d+'
RULE_LEVELS = ['recommended', 'aggressive']
MATURITY_LEVELS = ['development', 'testing',
                   'staged', 'production', 'deprecated']
OPERATORS = ['equals']
OS_OPTIONS = ['windows', 'linux', 'macos',
              'solaris']  # need to verify with ecs
INTERVAL_PATTERN = r'\d+[mshd]'
MITRE_URL_PATTERN = r'https://attack.mitre.org/{type}/T[A-Z0-9]+/'

NONFORMATTED_FIELDS = 'note',


# kibana/.../siem/server/lib/detection_engine/routes/schemas/add_prepackaged_rules_schema.ts
#                           /detection_engine/routes/schemas/schemas.ts
# rule_id is required here
# output_index is not allowed (and instead the space index must be used)
# immutable defaults to true instead of to false and if it is there can only be true
# enabled defaults to false instead of true
# version is a required field that must exist

# rule types
MACHINE_LEARNING = 'machine_learning'
SAVED_QUERY = 'saved_query'
QUERY = 'query'
THRESHOLD = 'threshold'

RULE_TYPES = [MACHINE_LEARNING, SAVED_QUERY, QUERY, THRESHOLD]


class FilterMetadata(jsl.Document):
    """Base class for siem rule meta filters."""

    negate = jsl.BooleanField()
    type = jsl.StringField()
    key = jsl.StringField()
    value = jsl.StringField()
    disabled = jsl.BooleanField()
    indexRefName = jsl.StringField()
    alias = jsl.StringField()  # null acceptable
    params = jsl.DictField(properties={'query': jsl.StringField()})


class FilterQuery(jsl.Document):
    """Base class for siem rule query filters."""

    match = jsl.DictField({
        'event.action': jsl.DictField(properties={
            'query': jsl.StringField(),
            'type': jsl.StringField()
        })
    })


class FilterState(jsl.Document):
    """Base class for siem rule $state filters."""

    store = jsl.StringField()


class FilterExists(jsl.Document):
    """Base class for siem rule $state filters."""

    field = jsl.StringField()


class Filters(jsl.Document):
    """Schema for filters"""

    exists = jsl.DocumentField(FilterExists)
    meta = jsl.DocumentField(FilterMetadata)
    state = jsl.DocumentField(FilterState, name='$state')
    query = jsl.DocumentField(FilterQuery)


class RiskScoreMapping(jsl.Document):
    """Risk score mapping."""

    field = jsl.StringField(required=True)
    operator = jsl.StringField(required=False, enum=OPERATORS)
    value = jsl.StringField(required=False)


class SeverityMapping(jsl.Document):
    """Severity mapping."""

    field = jsl.StringField(required=True)
    operator = jsl.StringField(required=False, enum=OPERATORS)
    value = jsl.StringField(required=False)
    severity = jsl.StringField(required=False)


class ThresholdMapping(jsl.Document):
    """Threshold mapping."""

    field = jsl.StringField(required=True, default="")
    value = jsl.IntField(minimum=1, required=True)


class ThreatTactic(jsl.Document):
    """Threat tactics."""

    id = jsl.StringField(enum=TACTICS_MAP.values())
    name = jsl.StringField(enum=TACTICS)
    reference = jsl.StringField(MITRE_URL_PATTERN.format(type='tactics'))


class ThreatTechnique(jsl.Document):
    """Threat tactics."""

    id = jsl.StringField(enum=list(technique_lookup))
    name = jsl.StringField(enum=TECHNIQUES)
    reference = jsl.StringField(MITRE_URL_PATTERN.format(type='techniques'))


class Threat(jsl.Document):
    """Threat framework mapping such as MITRE ATT&CK."""

    framework = jsl.StringField(default='MITRE ATT&CK', required=True)
    tactic = jsl.DocumentField(ThreatTactic, required=True)
    technique = jsl.ArrayField(
        jsl.DocumentField(ThreatTechnique), required=True)


class SiemRuleApiSchema(jsl.Document):
    """Schema for siem rule in API format."""

    actions = jsl.ArrayField(required=False)
    author = jsl.ArrayField(jsl.StringField(
        default="Elastic"), required=True, min_items=1)
    building_block_type = jsl.StringField(required=False)
    description = jsl.StringField(required=True)
    # api defaults to false if blank
    enabled = jsl.BooleanField(default=False, required=False)
    exceptions_list = jsl.ArrayField(required=False)
    # _ required since `from` is a reserved word in python
    from_ = jsl.StringField(required=False, default='now-6m', name='from')
    false_positives = jsl.ArrayField(jsl.StringField(), required=False)
    filters = jsl.ArrayField(jsl.DocumentField(Filters))
    interval = jsl.StringField(
        pattern=INTERVAL_PATTERN, default='5m', required=False)
    license = jsl.StringField(required=True, default="Elastic License")
    max_signals = jsl.IntField(
        minimum=1, required=False, default=100)  # cap a max?
    meta = jsl.DictField(required=False)
    name = jsl.StringField(required=True)
    note = jsl.StringField(required=False)
    # output_index = jsl.StringField(required=False)  # this is NOT allowed!
    references = jsl.ArrayField(jsl.StringField(), required=False)
    risk_score = jsl.IntField(minimum=0, maximum=100,
                              required=True, default=21)
    risk_score_mapping = jsl.ArrayField(jsl.DocumentField(
        RiskScoreMapping), required=False, min_items=1)
    rule_id = jsl.StringField(pattern=UUID_PATTERN, required=True)
    rule_name_override = jsl.StringField(required=False)
    severity = jsl.StringField(
        enum=['low', 'medium', 'high', 'critical'], default='low', required=True)
    severity_mapping = jsl.ArrayField(jsl.DocumentField(
        SeverityMapping), required=False, min_items=1)
    # saved_id - type must be 'saved_query' to allow this or else it is forbidden
    tags = jsl.ArrayField(jsl.StringField(), required=False)
    throttle = jsl.StringField(required=False)
    timeline_id = jsl.StringField(required=False)
    timeline_title = jsl.StringField(required=False)
    timestamp_override = jsl.StringField(required=False)
    to = jsl.StringField(required=False, default='now')
    # require this to be always validated with a role
    # type = jsl.StringField(enum=[MACHINE_LEARNING, QUERY, SAVED_QUERY], required=True)
    threat = jsl.ArrayField(jsl.DocumentField(
        Threat), required=False, min_items=1)

    with jsl.Scope(MACHINE_LEARNING) as ml_scope:
        ml_scope.anomaly_threshold = jsl.IntField(required=True, minimum=0)
        ml_scope.machine_learning_job_id = jsl.StringField(required=True)
        ml_scope.type = jsl.StringField(
            enum=[MACHINE_LEARNING], required=True, default=MACHINE_LEARNING)

    with jsl.Scope(SAVED_QUERY) as saved_id_scope:
        saved_id_scope.index = jsl.ArrayField(
            jsl.StringField(), required=False)
        saved_id_scope.saved_id = jsl.StringField(required=True)
        saved_id_scope.type = jsl.StringField(
            enum=[SAVED_QUERY], required=True, default=SAVED_QUERY)

    with jsl.Scope(QUERY) as query_scope:
        query_scope.index = jsl.ArrayField(jsl.StringField(), required=False)
        # this is not required per the API but we will enforce it here
        query_scope.language = jsl.StringField(
            enum=['kuery', 'lucene'], required=True, default='kuery')
        query_scope.query = jsl.StringField(required=True)
        query_scope.type = jsl.StringField(
            enum=[QUERY], required=True, default=QUERY)

    with jsl.Scope(THRESHOLD) as threshold_scope:
        threshold_scope.index = jsl.ArrayField(
            jsl.StringField(), required=False)
        # this is not required per the API but we will enforce it here
        threshold_scope.language = jsl.StringField(
            enum=['kuery', 'lucene'], required=True, default='kuery')
        threshold_scope.query = jsl.StringField(required=True)
        threshold_scope.type = jsl.StringField(
            enum=[THRESHOLD], required=True, default=THRESHOLD)
        threshold_scope.threshold = jsl.DocumentField(
            ThresholdMapping, required=True)


class VersionedApiSchema(SiemRuleApiSchema):
    """Schema for siem rule in API format with version."""

    version = jsl.IntField(minimum=1, default=1, required=True)


class SiemRuleTomlMetadata(jsl.Document):
    """Schema for siem rule toml metadata."""

    creation_date = jsl.StringField(
        required=True, pattern=DATE_PATTERN, default=time.strftime('%Y/%m/%d'))

    # added to query with rule.optimize()
    # rule validated against each ecs schema contained
    ecs_version = jsl.ArrayField(
        jsl.StringField(pattern=VERSION_PATTERN, required=True, default=ecs.get_max_version()), required=True)
    maturity = jsl.StringField(
        enum=MATURITY_LEVELS, default='development', required=True)

    # if present, add to query
    os_type_list = jsl.ArrayField(
        jsl.StringField(enum=OS_OPTIONS), required=False)
    related_endpoint_rules = jsl.ArrayField(jsl.ArrayField(jsl.StringField(), min_items=2, max_items=2),
                                            required=False)
    updated_date = jsl.StringField(
        required=True, pattern=DATE_PATTERN, default=time.strftime('%Y/%m/%d'))


class SiemRuleTomlSchema(jsl.Document):
    """Schema for siem rule in management toml format."""

    metadata = jsl.DocumentField(SiemRuleTomlMetadata)
    rule = jsl.DocumentField(SiemRuleApiSchema)


class Package(jsl.Document):
    """Schema for siem rule staging."""


class MappingCount(jsl.Document):
    """Mapping count schema."""

    count = jsl.IntField(minimum=0, required=True)
    rta_name = jsl.StringField(pattern=r'[a-zA-Z-_]+', required=True)
    rule_name = jsl.StringField(required=True)
    sources = jsl.ArrayField(jsl.StringField(), min_items=1)


@cached
def get_schema(role, as_rule=False, versioned=False):
    """Get applicable schema by role type and rule format."""
    if versioned:
        cls = VersionedApiSchema
    else:
        cls = SiemRuleTomlSchema if as_rule else SiemRuleApiSchema

    return cls.get_schema(ordered=True, role=role)


@cached
def schema_validate(contents, as_rule=False, versioned=False):
    """Validate against all schemas until first hit."""
    assert isinstance(contents, dict)
    role = contents.get('rule', {}).get(
        'type') if as_rule else contents.get('type')

    if not role:
        raise ValueError('Missing rule type!')

    return jsonschema.validate(contents, get_schema(role, as_rule, versioned))


metadata_schema = SiemRuleTomlMetadata.get_schema(ordered=True)
package_schema = Package.get_schema(ordered=True)
mapping_schema = MappingCount.get_schema(ordered=True)


def validate_rta_mapping(mapping):
    """Validate the RTA mapping."""
    jsonschema.validate(mapping, mapping_schema)

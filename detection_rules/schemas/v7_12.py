# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Definitions for rule metadata and schemas."""

import jsl

from .v7_11 import ApiSchema711
from .v7_9 import ThresholdMapping


class ApiSchema712(ApiSchema711):
    """Schema for siem rule in API format."""

    STACK_VERSION = "7.12"

    # there might be a bug in jsl that requires us to redefine these here
    query_scope = ApiSchema711.query_scope
    saved_id_scope = ApiSchema711.saved_id_scope
    ml_scope = ApiSchema711.ml_scope
    eql_scope = ApiSchema711.eql_scope

    class ThresholdMappingV12(ThresholdMapping):
        """7.12 schema for threshold mapping."""

        class ThresholdCardinality(jsl.Document):
            """Threshold cardinality field."""

            field = jsl.StringField(required=True)
            value = jsl.IntField(minimum=1, required=True)

        field = jsl.ArrayField(jsl.StringField(required=True, default=""))
        cardinality = jsl.DocumentField(ThresholdCardinality, required=False)

    threshold_scope = ApiSchema711.threshold_scope
    threshold_scope.threshold = jsl.DocumentField(ThresholdMappingV12, required=True)

    @classmethod
    def downgrade(cls, target_cls, document, role=None):
        """Remove 7.12 additions from the rule."""
        # ignore when this method is inherited by subclasses
        if cls in (ApiSchema712, ApiSchema712.versioned()) and 'threshold' in document:
            threshold = document['threshold']
            threshold_field = threshold['field']

            # attempt to convert threshold field to a string
            if len(threshold_field) > 1:
                raise ValueError('Cannot downgrade a threshold rule that has multiple threshold fields defined')
            if threshold.get('cardinality', {}).get('field') or threshold.get('cardinality', {}).get('value'):
                raise ValueError('Cannot downgrade a threshold rule that has a defined cardinality')

            document = document.copy()
            document["threshold"] = document["threshold"].copy()
            # if cardinality was defined with no field or value
            document['threshold'].pop('cardinality', None)
            document["threshold"]["field"] = document["threshold"]["field"][0]

        # now strip any any unrecognized properties
        return target_cls.strip_additional_properties(document, role)

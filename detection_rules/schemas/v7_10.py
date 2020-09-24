# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Definitions for rule metadata and schemas."""

import jsl
from .v7_8 import Threat as Threat78, MITRE_URL_PATTERN
from .v7_9 import ApiSchema79


# rule types
EQL = "eql"


class Threat710(Threat78):
    """Threat framework mapping such as MITRE ATT&CK."""

    class ThreatTechnique(Threat78.ThreatTechnique):
        """Patched threat.technique to add threat.technique.subtechnique."""

        class ThreatSubTechnique(jsl.Document):
            id = jsl.StringField(required=True)
            name = jsl.StringField(required=True)
            reference = jsl.StringField(MITRE_URL_PATTERN.format(type='techniques') + r"[0-9]+/")

        subtechnique = jsl.ArrayField(jsl.DocumentField(ThreatSubTechnique))

    # override the `technique` field definition
    technique = jsl.ArrayField(jsl.DocumentField(ThreatTechnique), required=True)


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

    threat = jsl.ArrayField(jsl.DocumentField(Threat710))

    with jsl.Scope(EQL) as eql_scope:
        eql_scope.index = jsl.ArrayField(jsl.StringField(), required=False)
        eql_scope.query = jsl.StringField(required=True)
        eql_scope.language = jsl.StringField(enum=[EQL], required=True, default=EQL)
        eql_scope.type = jsl.StringField(enum=[EQL], required=True)

    with jsl.Scope(jsl.DEFAULT_ROLE) as default_scope:
        default_scope.type = type

    @classmethod
    def downgrade(cls, target_cls, document, role=None):
        """Remove 7.10 additions from the rule."""
        # ignore when this method is inherited by subclasses
        if cls == ApiSchema710 and "threat" in document:
            threat_field = list(document["threat"])
            for threat in threat_field:
                if "technique" in threat:
                    threat["technique"] = [t.copy() for t in threat["technique"]]

                    for technique in threat["technique"]:
                        technique.pop("subtechnique", None)

            document = document.copy()
            document["threat"] = threat_field

        # now strip any any unrecognized properties
        return target_cls.strip_additional_properties(document, role)

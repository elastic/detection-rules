# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Definitions for rule metadata and schemas."""

import jsl
from .v7_8 import Threat as Threat78, MITRE_URL_PATTERN
from .v7_10 import ApiSchema710


class Threat711(Threat78):
    """Threat framework mapping such as MITRE ATT&CK."""

    class ThreatTechnique(Threat78.ThreatTechnique):
        """Patched threat.technique to add threat.technique.subtechnique."""

        class ThreatSubTechnique(jsl.Document):
            id = jsl.StringField(required=True)
            name = jsl.StringField(required=True)
            reference = jsl.StringField(MITRE_URL_PATTERN.format(type='techniques') + r"[0-9]+/")

        subtechnique = jsl.ArrayField(jsl.DocumentField(ThreatSubTechnique), required=False)

    # override the `technique` field definition
    technique = jsl.ArrayField(jsl.DocumentField(ThreatTechnique), required=True)


class ApiSchema711(ApiSchema710):
    """Schema for siem rule in API format."""

    STACK_VERSION = "7.11"

    threat = jsl.ArrayField(jsl.DocumentField(Threat711))

    @classmethod
    def downgrade(cls, target_cls, document, role=None):
        """Remove 7.11 additions from the rule."""
        # ignore when this method is inherited by subclasses
        if cls == ApiSchema711 and "threat" in document:
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

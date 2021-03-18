# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Definitions for rule metadata and schemas."""

import jsl
from .v7_8 import Threat as Threat78, MITRE_URL_PATTERN
from .v7_10 import ApiSchema710
from ..attack import sub_technique_id_list


class Threat711(Threat78):
    """Threat framework mapping such as MITRE ATT&CK."""

    class ThreatTechnique(Threat78.ThreatTechnique):
        """Patched threat.technique to add threat.technique.subtechnique."""

        class ThreatSubTechnique(jsl.Document):
            id = jsl.StringField(enum=sub_technique_id_list, required=True)
            name = jsl.StringField(required=True)
            reference = jsl.StringField(MITRE_URL_PATTERN.format(type='techniques') + r"[0-9]+/")

        subtechnique = jsl.ArrayField(jsl.DocumentField(ThreatSubTechnique), required=False)

    # override the `technique` field definition
    technique = jsl.ArrayField(jsl.DocumentField(ThreatTechnique), required=False)


class ApiSchema711(ApiSchema710):
    """Schema for siem rule in API format."""

    STACK_VERSION = "7.11"

    threat = jsl.ArrayField(jsl.DocumentField(Threat711))

    @classmethod
    def downgrade(cls, target_cls, document, role=None):
        """Remove 7.11 additions from the rule."""
        # ignore when this method is inherited by subclasses
        if cls in (ApiSchema711, ApiSchema711.versioned()) and "threat" in document:
            v711_threats = document.get("threat", [])
            v710_threats = []

            for threat in v711_threats:
                # drop tactic without threat
                if "technique" not in threat:
                    continue

                threat = threat.copy()
                threat["technique"] = [t.copy() for t in threat["technique"]]

                # drop subtechniques
                for technique in threat["technique"]:
                    technique.pop("subtechnique", None)

                v710_threats.append(threat)

            document = document.copy()
            document.pop("threat")

            # only add if the array is not empty
            if len(v710_threats) > 0:
                document["threat"] = v710_threats

        # now strip any any unrecognized properties
        return target_cls.strip_additional_properties(document, role)

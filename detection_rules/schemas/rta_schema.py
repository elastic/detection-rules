# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import jsl
import jsonschema


class MappingCount(jsl.Document):
    """Mapping count schema."""

    count = jsl.IntField(minimum=0, required=True)
    rta_name = jsl.StringField(pattern=r'[a-zA-Z-_]+', required=True)
    rule_name = jsl.StringField(required=True)
    sources = jsl.ArrayField(jsl.StringField(), min_items=1)


mapping_schema = MappingCount.get_schema()


def validate_rta_mapping(mapping):
    """Validate the RTA mapping."""
    jsonschema.validate(mapping, mapping_schema)

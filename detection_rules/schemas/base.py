# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Definitions for rule metadata and schemas."""

import time

import jsl
import jsonschema

from .definitions import (
    DATE_PATTERN, MATURITY_LEVELS, OS_OPTIONS, UUID_PATTERN, VERSION_PATTERN, VERSION_W_MASTER_PATTERN
)
from ..utils import cached


class MarkdownField(jsl.StringField):
    """Helper class for noting which fields are markdown."""

    def __init__(self, *args, **kwargs):
        kwargs["format"] = "markdown"
        jsl.StringField.__init__(self, *args, **kwargs)


class GenericSchema(jsl.Document):
    """Generic schema with helper methods."""

    @classmethod
    @cached
    def get_schema(cls, role=jsl.DEFAULT_ROLE, ordered=False):
        """Wrap jsl.Document.get_schema to add caching."""
        return super(GenericSchema, cls).get_schema(role=role, ordered=ordered)

    @classmethod
    @cached
    def validate(cls, document, role=None):
        """Validate a document against this schema."""
        schema = cls.get_schema(role=role)
        return jsonschema.validate(document, schema)

    @classmethod
    def strip_additional_properties(cls, document, role=None):
        """Strip properties that aren't defined in the schema."""
        if role is None:
            role = document.get("type", jsl.DEFAULT_ROLE)

        if role not in cls.RULE_TYPES:
            raise ValueError(f"Unsupported rule type {role}")

        target_schema = cls.get_schema(role)["properties"]
        stripped = {}

        # simple version, can customize or walk structures deeper when we have a need and use case
        for field in target_schema:
            if field in document:
                stripped[field] = document[field]
            elif target_schema[field].get("required") and "default" in target_schema:
                stripped[field] = target_schema[field]["required"]

        # finally, validate against the json schema
        cls.validate(stripped, role)
        return stripped


class TomlMetadata(GenericSchema):
    """Schema for rule toml metadata."""

    creation_date = jsl.StringField(required=True, pattern=DATE_PATTERN, default=time.strftime('%Y/%m/%d'))

    # rule validated against each ecs schema contained
    beats_version = jsl.StringField(pattern=VERSION_PATTERN, required=False)
    comments = jsl.StringField(required=False)
    ecs_versions = jsl.ArrayField(jsl.StringField(pattern=VERSION_W_MASTER_PATTERN, required=True), required=False)
    maturity = jsl.StringField(enum=MATURITY_LEVELS, default='development', required=True)

    os_type_list = jsl.ArrayField(jsl.StringField(enum=OS_OPTIONS), required=False)
    query_schema_validation = jsl.BooleanField(required=False)
    related_endpoint_rules = jsl.ArrayField(jsl.ArrayField(jsl.StringField(), min_items=2, max_items=2),
                                            required=False)
    updated_date = jsl.StringField(required=True, pattern=DATE_PATTERN, default=time.strftime('%Y/%m/%d'))


class BaseApiSchema(GenericSchema):
    """Base API schema with generic methods."""

    STACK_VERSION = str()

    rule_id = jsl.StringField(pattern=UUID_PATTERN, required=True)
    type = jsl.StringField(required=True)

    @classmethod
    @cached
    def versioned(cls):
        """Get a subclass that is version aware."""
        attrs = {"version": jsl.IntField(minimum=1, default=1, required=True)}
        return type("Versioned" + cls.__name__, (cls, ), attrs)

    @classmethod
    def validate(cls, document, role=None, toml=False):
        """Validate a document against this API schema."""
        if toml:
            role = role or document.get("rule", {}).get("type")
            return cls.toml_schema().validate(document, role=role)

        role = role or document.get("type")
        return super(BaseApiSchema, cls).validate(document, role=role)

    @classmethod
    @cached
    def markdown_fields(cls, role=None):
        properties = cls.get_schema(role)["properties"]
        return {p for p in properties if properties[p].get("format") == "markdown"}

    @classmethod
    @cached
    def toml_schema(cls):
        """Create a custom TOML schema class that includes this API schema."""
        attrs = {
            "metadata": jsl.DocumentField(TomlMetadata, required=True),
            "rule": jsl.DocumentField(cls, required=True)
        }
        return type("Versioned" + cls.__name__, (GenericSchema, ), attrs)

    @classmethod
    def downgrade(cls, target_cls, document, role=None):
        """Downgrade from one schema to its predecessor."""
        # by default, we'll just strip extra properties
        # different schemas can override this to provide a more advanced migration path
        # and deeper evaluation of the schema.
        return target_cls.strip_additional_properties(document, role=role)

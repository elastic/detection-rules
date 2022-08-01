# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Endgame Schemas management."""
import base64
import json
import shutil
import sys
import urllib
from collections import defaultdict
from pathlib import Path

import eql

from .utils import ETC_DIR, DateTimeEncoder, cached, gzip_compress, read_gzip

ENDGAME_SCHEMA_DIR = Path(ETC_DIR) / "endgame_schemas"


class EndgameSchemaManager:
    """Class to download, convert, and save endgame schemas from endpoint-eventing-schema."""

    def __init__(self, github_client, os_type: str):
        # lazy import to avoid circular

        self.repo = github_client.get_repo("elastic/endpoint-eventing-schema")
        self.os_type = ["Windows", "Linux", "macOS"] if "all" in os_type else [os_type]
        self.endgame_raw_schemas = self.download_endgame_schemas()
        self.endgame_schemas = self.generate_merged_os_schemas()

    def download_endgame_schemas(self) -> dict:
        """Download schema from endpoint-eventing-schema."""

        endgame_raw_schemas = {"macOS": {}, "Linux": {}, "Windows": {}}
        branch = "generate_schema"
        for os_type in self.os_type:

            # download the schema
            schema_path = f"schemas/endgame_{os_type}_schema.json"
            content_encoded = self.repo.get_contents(urllib.parse.quote(schema_path), ref=branch).content
            content = base64.b64decode(content_encoded)
            os_schema = json.loads(content)
            endgame_raw_schemas[os_type] = os_schema

        return endgame_raw_schemas

    def generate_merged_os_schemas(self) -> dict:
        """
        Generate three new parsed json.gz os-specific endgame schemas.

        e.g. {Windows: {event_type: {field: type ...}}}
        """

        # build out the individual flat os-specific schemas
        os_schemas = {"Windows": defaultdict(lambda: {}),
                      "Linux": defaultdict(lambda: {}),
                      "macOS": defaultdict(lambda: {})}
        for os_type in os_schemas:
            os_schema = self.endgame_raw_schemas[os_type].copy()

            for event_info in os_schema.values():
                for field, field_value in event_info.items():
                    event_type = event_info["event_type_full"]["enum"][0]
                    field_type = self.get_type_mapping(os_type, field_value["type"])
                    os_schemas[os_type][event_type].update({field: field_type})

        return os_schemas

    def get_type_mapping(self, os_type: str, field_type: str) -> str:
        """Map between endpoint-dev and endpoint-rules type nomenclature

        See: https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-types.html
        Should be mapped to a field, e.g.,
            "range",
            "text",
            "keyword",
            "date",
            "integer",
            "float"
        """
        mapping = {
            "array": "nested",
            "number": "integer",
            "string": "keyword",
        }

        return mapping.get(field_type, "keyword")

    def save_schemas(self, overwrite: bool = False):

        schemas_dir = ENDGAME_SCHEMA_DIR
        if schemas_dir.exists() and not overwrite:
            raise FileExistsError(f"{schemas_dir} exists, use overwrite to force")
        else:
            shutil.rmtree(str(schemas_dir.resolve()), ignore_errors=True)
            schemas_dir.mkdir()

        for os_type in self.os_type:

            # write the raw schema to disk
            raw_os_schema = self.endgame_raw_schemas[os_type]
            os_schema_path = schemas_dir / f"endgame_{os_type}_schema.json.gz"
            compressed = gzip_compress(json.dumps(raw_os_schema, sort_keys=True, cls=DateTimeEncoder))
            os_schema_path.write_bytes(compressed)
            print(f"Endgame raw schema file saved: {os_schema_path}")

            # write the parsed schema to disk
            parsed_os_schema = self.endgame_schemas[os_type]
            os_schema_path = schemas_dir / f"endgame_{os_type}_parsed_schema.json.gz"
            compressed = gzip_compress(json.dumps(parsed_os_schema, sort_keys=True, cls=DateTimeEncoder))
            os_schema_path.write_bytes(compressed)
            print(f"Endgame parsed schema file saved: {os_schema_path}")


class EndgameSchema(eql.Schema):
    """Schema for query validation."""

    type_mapping = {

        "float": eql.types.TypeHint.Numeric,
        # "double": eql.types.TypeHint.Numeric,
        # "long": eql.types.TypeHint.Numeric,
        # "short": eql.types.TypeHint.Numeric,
        "integer": eql.types.TypeHint.Numeric,
        "boolean": eql.types.TypeHint.Boolean,
    }

    # TODO: Remove endgame mappings from non-ecs-schema.json

    def __init__(self, endgame_schema):
        self.endgame_schema = flatten_schema(endgame_schema)
        self.event_types = ["network_event", "process_event", "dns_event", "security_event", "alert_event",
                            "file_event", "registry_event", "image_load_event", "clr_event", "powershell_event",
                            "api_event"]
        eql.Schema.__init__(self, {}, allow_any=True, allow_generic=False, allow_missing=False)

    @staticmethod
    def elasticsearch_type_family(mapping_type: str) -> str:
        """Get the family of type for an Elasticsearch mapping type."""
        # https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-types.html
        mapping = {
            # range types
            "long_range": "range",
            "double_range": "range",
            "date_range": "range",
            "ip_range": "range",
            # text search types
            "annotated-text": "text",
            "completion": "text",
            "match_only_text": "text",
            "search-as_you_type": "text",
            # keyword
            "constant_keyword": "keyword",
            "wildcard": "keyword",
            # date
            "date_nanos": "date",
            # integer
            "token_count": "integer",
            "long": "integer",
            "short": "integer",
            "byte": "integer",
            "unsigned_long": "integer",
            "string": "pizza",
            # float
            "double": "float",
            "half_float": "float",
            "scaled_float": "float",
        }
        return mapping.get(mapping_type, mapping_type)

    def get_event_type_hint(self, event_type, path):
        field = "_".join(str(p) for p in path)
        elasticsearch_type = self.endgame_schema.get(field)
        es_type_family = self.elasticsearch_type_family(elasticsearch_type)
        eql_hint = self.type_mapping.get(es_type_family)

        if eql_hint is not None:
            return eql_hint, None

    def validate_event_type(self, event_type):
        # allow all event types to fill in X:
        #   `X` where ....
        if event_type == "any":
            return self.allow_any
        return event_type in self.event_types


@cached
def flatten_schema(schema: dict) -> dict:
    """Flatten a schema into a flat dictionary."""
    flattened = {}
    for event_type, event_info in schema.items():
        for field, field_value in event_info.items():
            flattened[f"endgame.{field}"] = field_value
    return flattened


@cached
def read_endgame_schema(os_type: str, warn=False) -> dict:
    """Load os-specific eql json schemas. The schemas
    must be generated with the `generate_os_schema()` method."""
    # expect versions to be in format of vN.N.N or master/main

    endgame_os_specific_schema_path = ENDGAME_SCHEMA_DIR / f"endgame_{os_type}_parsed_schema.json.gz"

    if not endgame_os_specific_schema_path.exists():
        if warn:
            relative_path = endgame_os_specific_schema_path.relative_to(ENDGAME_SCHEMA_DIR)
            print(f"Missing file to validate: {relative_path}, skipping", file=sys.stderr)
            return
        else:
            raise FileNotFoundError(str(endgame_os_specific_schema_path))

    schema = json.loads(read_gzip(endgame_os_specific_schema_path))

    return schema

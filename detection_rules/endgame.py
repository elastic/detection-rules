# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Endgame Schemas management."""
import json
import shutil
import sys
from pathlib import Path

import eql

from .utils import ETC_DIR, DateTimeEncoder, cached, gzip_compress, read_gzip

ENDGAME_SCHEMA_DIR = Path(ETC_DIR) / "endgame_schemas"


class EndgameSchemaManager:
    """Class to download, convert, and save endgame schemas from endpoint-eventing-schema."""

    def __init__(self, github_client, endgame_version: str):
        # self.repo = github_client.get_repo("elastic/endpoint-eventing-schema")
        self.endgame_version = endgame_version
        self.endgame_raw_schema = self.download_endgame_schema()
        self.endgame_schema = self.flatten(self.endgame_raw_schema['mappings']['properties'])

    def download_endgame_schema(self) -> dict:
        """Download schema from TBD."""

        # TODO: Download schema from TBD
        # Temporarily, use the static mapping.json file downloaded from the
        # Endgame UI until we have an authoritative place to download the file.
        endgame_mapping_path = ENDGAME_SCHEMA_DIR / "v190" / "mapping.json"
        endgame_mapping = json.loads(endgame_mapping_path.read_bytes())
        return endgame_mapping

    def flatten(self, mapping) -> dict:
        """Flatten Endgame - ECS mapping into a flat dictionary schema."""
        flattened = {}
        for k, v in mapping.items():
            if "properties" in k or "fields" in k:
                flattened.update((vk, vv) for vk, vv in self.flatten(v).items())
            elif k in ["ignore_above", "norms", "scaling_factor"]:
                continue
            elif isinstance(v, dict):
                for vk, vv in self.flatten(v).items():
                    if "type" in vk:
                        flattened[k] = vv
                    else:
                        flattened[k + "." + vk] = vv
            else:
                flattened[k] = v
        return flattened

    def save_schemas(self, overwrite: bool = False):

        schemas_dir = ENDGAME_SCHEMA_DIR / self.endgame_version
        if schemas_dir.exists() and not overwrite:
            raise FileExistsError(f"{schemas_dir} exists, use overwrite to force")
        else:
            shutil.rmtree(str(schemas_dir.resolve()), ignore_errors=True)
            schemas_dir.mkdir()

        # write the raw schema to disk
        raw_os_schema = self.endgame_raw_schema
        os_schema_path = schemas_dir / "endgame_ecs_mapping.json.gz"
        compressed = gzip_compress(json.dumps(raw_os_schema, sort_keys=True, cls=DateTimeEncoder))
        os_schema_path.write_bytes(compressed)
        print(f"Endgame raw schema file saved: {os_schema_path}")

        # write the parsed schema to disk
        os_schema_path = schemas_dir / "endgame_flat.json.gz"
        compressed = gzip_compress(json.dumps(self.endgame_schema, sort_keys=True, cls=DateTimeEncoder))
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
        self.endgame_schema = endgame_schema
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


@cached
def read_endgame_schema(endgame_version: str, warn=False) -> dict:
    """Load Endgame json schemas. The schemas
    must be generated with the `generate_os_schema()` method."""
    # expect versions to be in format of vN.N.N or master/main

    endgame_schema_path = ENDGAME_SCHEMA_DIR / endgame_version / "endgame_flat.json.gz"

    if not endgame_schema_path.exists():
        if warn:
            relative_path = endgame_schema_path.relative_to(ENDGAME_SCHEMA_DIR)
            print(f"Missing file to validate: {relative_path}, skipping", file=sys.stderr)
            return
        else:
            raise FileNotFoundError(str(endgame_schema_path))

    schema = json.loads(read_gzip(endgame_schema_path))

    return schema

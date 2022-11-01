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
    """Endgame Class to download, convert, and save endgame schemas from endgame-evecs."""

    def __init__(self, github_client, endgame_version: str):
        self.repo = github_client.get_repo("elastic/endgame-evecs")
        self.endgame_version = endgame_version
        self.endgame_schema = self.download_endgame_schema()

    def download_endgame_schema(self) -> dict:
        """Download schema from endgame-evecs."""

        # Use the static mapping.json file downloaded from the endgame-evecs repo.
        main_branch = self.repo.get_branch("master")
        main_branch_sha = main_branch.commit.sha
        schema_path = "pkg/mapper/ecs/schema.json"
        contents = self.repo.get_contents(schema_path, ref=main_branch_sha)
        endgame_mapping = json.loads(contents.decoded_content.decode())

        return endgame_mapping

    def save_schemas(self, overwrite: bool = False):
        """Save the endgame schemas to the etc/endgame_schemas directory."""

        schemas_dir = ENDGAME_SCHEMA_DIR / self.endgame_version
        if schemas_dir.exists() and not overwrite:
            raise FileExistsError(f"{schemas_dir} exists, use overwrite to force")
        else:
            shutil.rmtree(str(schemas_dir.resolve()), ignore_errors=True)
            schemas_dir.mkdir()

        # write the raw schema to disk
        raw_os_schema = self.endgame_schema
        os_schema_path = schemas_dir / "endgame_ecs_mapping.json.gz"
        compressed = gzip_compress(json.dumps(raw_os_schema, sort_keys=True, cls=DateTimeEncoder))
        os_schema_path.write_bytes(compressed)
        print(f"Endgame raw schema file saved: {os_schema_path}")


class EndgameSchema(eql.Schema):
    """Endgame schema for query validation."""

    type_mapping = {
        "keyword": eql.types.TypeHint.String,
        "ip": eql.types.TypeHint.String,
        "float": eql.types.TypeHint.Numeric,
        "integer": eql.types.TypeHint.Numeric,
        "boolean": eql.types.TypeHint.Boolean,
        "text": eql.types.TypeHint.String,
    }

    def __init__(self, endgame_schema):
        self.endgame_schema = endgame_schema
        eql.Schema.__init__(self, {}, allow_any=True, allow_generic=False, allow_missing=False)

    def get_event_type_hint(self, event_type, path):
        from kql.parser import elasticsearch_type_family
        dotted = ".".join(str(p) for p in path)
        elasticsearch_type = self.endgame_schema.get(dotted)
        es_type_family = elasticsearch_type_family(elasticsearch_type)
        eql_hint = self.type_mapping.get(es_type_family)

        if eql_hint is not None:
            return eql_hint, None


@cached
def read_endgame_schema(endgame_version: str, warn=False) -> dict:
    """Load Endgame json schema. The schemas
    must be generated with the `download_endgame_schema()` method."""
    # expect versions to be in format of N.N.N or master/main

    endgame_schema_path = ENDGAME_SCHEMA_DIR / endgame_version / "endgame_ecs_mapping.json.gz"

    if not endgame_schema_path.exists():
        if warn:
            relative_path = endgame_schema_path.relative_to(ENDGAME_SCHEMA_DIR)
            print(f"Missing file to validate: {relative_path}, skipping", file=sys.stderr)
            return
        else:
            raise FileNotFoundError(str(endgame_schema_path))

    schema = json.loads(read_gzip(endgame_schema_path))

    return schema

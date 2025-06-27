# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Endgame Schemas management."""

import json
import shutil
import sys
from typing import Any

import eql  # type: ignore[reportMissingTypeStubs]
from github import Github

from .utils import ETC_DIR, DateTimeEncoder, cached, gzip_compress, read_gzip

ENDGAME_SCHEMA_DIR = ETC_DIR / "endgame_schemas"


class EndgameSchemaManager:
    """Endgame Class to download, convert, and save endgame schemas from endgame-evecs."""

    def __init__(self, github_client: Github, endgame_version: str) -> None:
        self.repo = github_client.get_repo("elastic/endgame-evecs")
        self.endgame_version = endgame_version
        self.endgame_schema = self.download_endgame_schema()

    def download_endgame_schema(self) -> dict[str, Any]:
        """Download schema from endgame-evecs."""

        # Use the static mapping.json file downloaded from the endgame-evecs repo.
        main_branch = self.repo.get_branch("master")
        main_branch_sha = main_branch.commit.sha
        schema_path = "pkg/mapper/ecs/schema.json"
        contents = self.repo.get_contents(schema_path, ref=main_branch_sha)
        return json.loads(contents.decoded_content.decode())  # type: ignore[reportAttributeAccessIssue]

    def save_schemas(self, overwrite: bool = False) -> None:
        """Save the endgame schemas to the etc/endgame_schemas directory."""

        schemas_dir = ENDGAME_SCHEMA_DIR / self.endgame_version
        if schemas_dir.exists() and not overwrite:
            raise FileExistsError(f"{schemas_dir} exists, use overwrite to force")
        shutil.rmtree(str(schemas_dir.resolve()), ignore_errors=True)
        schemas_dir.mkdir()

        # write the raw schema to disk
        raw_os_schema = self.endgame_schema
        os_schema_path = schemas_dir / "endgame_ecs_mapping.json.gz"
        compressed = gzip_compress(json.dumps(raw_os_schema, sort_keys=True, cls=DateTimeEncoder))
        _ = os_schema_path.write_bytes(compressed)
        print(f"Endgame raw schema file saved: {os_schema_path}")


class EndgameSchema(eql.Schema):
    """Endgame schema for query validation."""

    type_mapping: dict[str, Any] = {  # noqa: RUF012
        "keyword": eql.types.TypeHint.String,  # type: ignore[reportAttributeAccessIssue]
        "ip": eql.types.TypeHint.String,  # type: ignore[reportAttributeAccessIssue]
        "float": eql.types.TypeHint.Numeric,  # type: ignore[reportAttributeAccessIssue]
        "integer": eql.types.TypeHint.Numeric,  # type: ignore[reportAttributeAccessIssue]
        "boolean": eql.types.TypeHint.Boolean,  # type: ignore[reportAttributeAccessIssue]
        "text": eql.types.TypeHint.String,  # type: ignore[reportAttributeAccessIssue]
    }

    def __init__(self, endgame_schema: dict[str, Any]) -> None:
        self.endgame_schema = endgame_schema
        eql.Schema.__init__(self, {}, allow_any=True, allow_generic=False, allow_missing=False)  # type: ignore[reportUnknownMemberType]

    def get_event_type_hint(self, _: str, path: list[str]) -> None | tuple[Any, None]:  # type: ignore[reportIncompatibleMethodOverride]
        from kql.parser import elasticsearch_type_family  # type: ignore[reportMissingTypeStubs]

        dotted = ".".join(str(p) for p in path)
        elasticsearch_type = self.endgame_schema.get(dotted)
        es_type_family = elasticsearch_type_family(elasticsearch_type)  # type: ignore[reportArgumentType]
        eql_hint = self.type_mapping.get(es_type_family)

        if eql_hint:
            return eql_hint, None
        return None


@cached
def read_endgame_schema(endgame_version: str, warn: bool = False) -> dict[str, Any] | None:
    """Load Endgame json schema. The schemas
    must be generated with the `download_endgame_schema()` method."""
    # expect versions to be in format of N.N.N or master/main

    endgame_schema_path = ENDGAME_SCHEMA_DIR / endgame_version / "endgame_ecs_mapping.json.gz"

    if not endgame_schema_path.exists():
        if warn:
            relative_path = endgame_schema_path.relative_to(ENDGAME_SCHEMA_DIR)
            print(f"Missing file to validate: {relative_path}, skipping", file=sys.stderr)
            return None
        raise FileNotFoundError(str(endgame_schema_path))

    return json.loads(read_gzip(endgame_schema_path))

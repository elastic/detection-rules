# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from dataclasses import dataclass, field
from pathlib import Path

import esql

# Define the hunting directory path
HUNTING_DIR = Path(__file__).parent

# URLs for MITRE and Elastic documentation
ATLAS_URL = "https://atlas.mitre.org/techniques/"
ATTACK_URL = "https://attack.mitre.org/techniques/"

# Static mapping for specific integrations
STATIC_INTEGRATION_LINK_MAP = {"aws_bedrock.invocation": "aws_bedrock"}


@dataclass
class Hunt:
    """Dataclass to represent a hunt."""

    author: str
    description: str
    integration: list[str]
    uuid: str
    name: str
    language: list[str]
    license: str
    query: list[str]
    notes: list[str] | None = field(default_factory=list)  # type: ignore[reportUnknownVariableType]
    mitre: list[str] = field(default_factory=list)  # type: ignore[reportUnknownVariableType]
    references: list[str] | None = field(default_factory=list)  # type: ignore[reportUnknownVariableType]

    def __post_init__(self) -> None:
        """Post-initialization to determine which validation to apply."""
        if not self.query:
            raise ValueError(f"Hunt: {self.name} - Query field must be provided.")

        # Loop through each query in the array
        for q in self.query:
            query_start = q.strip().lower()

            # Only validate queries that start with "from" (ESQL queries)
            if query_start.startswith("from"):
                self.validate_esql_query(q)

    def validate_esql_query(self, query: str) -> None:
        """Validation logic for ESQL (AST KEEP / aggregate shape for Elastic hunts)."""
        if self.author != "Elastic":
            return

        try:
            tree = esql.parse_query(query)
        except Exception as exc:  # noqa: BLE001 — surface parse failures as hunt errors
            raise ValueError(f"Hunt: {self.name} contains an invalid ES|QL query: {exc}") from exc

        if not (esql.has_keep(tree) or esql.is_aggregate_query(tree)):
            raise ValueError(
                f"Hunt: {self.name} contains an ES|QL query that must contain either 'stats by' or 'keep' functions"
            )

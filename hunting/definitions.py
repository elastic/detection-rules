# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List

# Define the hunting directory path
HUNTING_DIR = Path(__file__).parent

# URLs for MITRE and Elastic documentation
ATLAS_URL = "https://atlas.mitre.org/techniques/"
ATTACK_URL = "https://attack.mitre.org/techniques/"

# Static mapping for specific integrations
STATIC_INTEGRATION_LINK_MAP = {
    'aws_bedrock.invocation': 'aws_bedrock'
}


@dataclass
class Hunt:
    """Dataclass to represent a hunt."""
    author: str
    description: str
    integration: List[str]
    uuid: str
    name: str
    language: List[str]
    license: str
    query: List[str]
    notes: Optional[List[str]] = field(default_factory=list)
    mitre: List[str] = field(default_factory=list)
    references: Optional[List[str]] = field(default_factory=list)

    def __post_init__(self):
        """Post-initialization to determine which validation to apply."""
        if not self.query:
            raise ValueError(f"Hunt: {self.name} - Query field must be provided.")

        # Loop through each query in the array
        for idx, q in enumerate(self.query):
            query_start = q.strip().lower()

            # Only validate queries that start with "from" (ESQL queries)
            if query_start.startswith("from"):
                self.validate_esql_query(q)

    def validate_esql_query(self, query: str) -> None:
        """Validation logic for ESQL."""
        query = query.lower()

        if self.author == "Elastic":
            # Regex patterns for checking "stats by" and "| keep"
            stats_by_pattern = re.compile(r'\bstats\b.*?\bby\b', re.DOTALL)
            keep_pattern = re.compile(r'\| keep', re.DOTALL)

            # Check if either "stats by" or "| keep" exists in the query
            if not stats_by_pattern.search(query) and not keep_pattern.search(query):
                raise ValueError(
                    f"Hunt: {self.name} contains an ES|QL query that must contain either 'stats by' or 'keep' functions."
                )

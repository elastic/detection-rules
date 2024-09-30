# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

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
    integration: list[str]
    uuid: str
    name: str
    language: list[str]
    license: str
    query: list[str]
    notes: Optional[list[str]] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    references: Optional[list[str]] = field(default_factory=list)

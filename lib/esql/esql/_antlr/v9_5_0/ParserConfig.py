# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""ANTLR parser base class with ES|QL configuration hooks."""

from __future__ import annotations

from typing import Any

from antlr4 import Parser


class ParserConfig(Parser):
    """Parser subclass expected by generated EsqlBaseParser."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.esql_config: dict[str, Any] = {}

    def setEsqlConfig(self, config: dict[str, Any] | None) -> None:
        """Attach runtime configuration (release vs dev, feature flags)."""
        self.esql_config = dict(config or {})

    def isDevVersion(self) -> bool:
        return bool(self.esql_config.get("dev_version", False))

    def isExternalDataSourcesEnabled(self) -> bool:
        return bool(self.esql_config.get("external_data_sources", False))

    def isCapabilityEnabled(self, name: str) -> bool:
        mapping = {
            "EXTERNAL_COMMAND": self.isExternalDataSourcesEnabled(),
        }
        if name in mapping:
            return mapping[name]
        return bool(self.esql_config.get(f"cap_{name}", False))

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""ANTLR lexer base class with ES|QL configuration hooks."""

from __future__ import annotations

from typing import Any

from antlr4 import Lexer


class LexerConfig(Lexer):
    """Lexer subclass expected by generated EsqlBaseLexer."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.esql_config: dict[str, Any] = {}
        self._promql_depth = 0

    def setEsqlConfig(self, config: dict[str, Any] | None) -> None:
        """Attach runtime configuration (release vs dev, feature flags)."""
        self.esql_config = dict(config or {})

    def isDevVersion(self) -> bool:
        """Return True when dev-only tokens should be accepted."""
        return bool(self.esql_config.get("dev_version", False))

    def isExternalDataSourcesEnabled(self) -> bool:
        """Return True when external data source commands are enabled."""
        return bool(self.esql_config.get("external_data_sources", False))

    def isCapabilityEnabled(self, name: str) -> bool:
        """Map EsqlCapabilities.Cap.* predicates to ParserConfig flags (release=False)."""
        mapping = {
            "EXTERNAL_COMMAND": self.isExternalDataSourcesEnabled(),
        }
        if name in mapping:
            return mapping[name]
        # Unknown/dev capabilities stay off in release mode unless explicitly set.
        return bool(self.esql_config.get(f"cap_{name}", False))

    def incPromqlDepth(self) -> None:
        self._promql_depth += 1

    def decPromqlDepth(self) -> None:
        if self._promql_depth > 0:
            self._promql_depth -= 1

    def resetPromqlDepth(self) -> None:
        self._promql_depth = 0

    def isPromqlQuery(self) -> bool:
        return self._promql_depth > 0

    def rewindToTokenStart(self, charsToKeep: int = 0) -> None:
        """Rewind lexer input/line/column to the start of the current token.

        Mirrors Elasticsearch `LexerConfig.rewindToTokenStart` used by
        lookahead-style lexer rules (e.g. `InExpression.g4` on 9.5+/main).
        """
        start = getattr(self, "_tokenStartCharIndex", None)
        if start is None or start < 0:
            return
        keep = int(charsToKeep)
        self._input.seek(start + keep)
        # antlr4-python uses _interp + _tokenStartColumn (not Java getInterpreter APIs)
        line = getattr(self, "_tokenStartLine", None)
        col = getattr(self, "_tokenStartColumn", None)
        interp = getattr(self, "_interp", None)
        if interp is not None:
            if line is not None and line >= 0:
                interp.line = line
            if col is not None and col >= 0:
                interp.column = col + keep

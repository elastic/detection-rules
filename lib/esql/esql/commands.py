# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Known ES|QL command names."""

from __future__ import annotations

__all__ = ("COMMANDS", "is_known_command")

COMMANDS: frozenset[str] = frozenset(
    {
        "from",
        "row",
        "show",
        "ts",
        "where",
        "keep",
        "drop",
        "eval",
        "stats",
        "sort",
        "limit",
        "rename",
        "grok",
        "dissect",
        "enrich",
        "mv_expand",
        "join",
        "fork",
        "completion",
        "inlinestats",
        "promql",
        "sample",
        "rerank",
        "change_point",
        "fuse",
        "set",
        "explain",
    }
)


def is_known_command(name: str) -> bool:
    return name.lower() in COMMANDS

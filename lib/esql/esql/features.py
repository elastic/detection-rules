# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Default ES|QL feature availability by stack version."""

from __future__ import annotations

from typing import NamedTuple

from .versions import Version

__all__ = ("FeatureRange", "ESQL_FEATURES", "feature_available")


class FeatureRange(NamedTuple):
    introduced: Version
    removed: Version | None = None


# Baseline map maintained with grammar sync; consumers may override via ParserConfig.
ESQL_FEATURES: dict[str, FeatureRange] = {
    "fork": FeatureRange(Version(8, 14)),
    "lookup_join": FeatureRange(Version(8, 12)),
    "kql_function": FeatureRange(Version(8, 15)),
    "inline_stats": FeatureRange(Version(8, 13)),
    "completion": FeatureRange(Version(8, 14)),
    "join": FeatureRange(Version(8, 12)),
    "lookup": FeatureRange(Version(8, 12)),
    "grok": FeatureRange(Version(8, 11)),
    "dissect": FeatureRange(Version(8, 11)),
    "enrich": FeatureRange(Version(8, 11)),
    "mv_expand": FeatureRange(Version(8, 11)),
    "rename": FeatureRange(Version(8, 11)),
    "promql": FeatureRange(Version(8, 15)),
    "time_series": FeatureRange(Version(8, 16)),
    "eql_function": FeatureRange(Version(9, 4)),
    "dev_explain": FeatureRange(Version(9, 0)),  # dev-only in release builds
    "external_data_sources": FeatureRange(Version(9, 0)),  # dev-only in release builds
}


def feature_available(name: str, stack_version: str | Version) -> bool:
    """Return True when *name* is available at *stack_version*."""
    version = Version.parse(stack_version)
    spec = ESQL_FEATURES.get(name)
    if spec is None:
        return True
    if version < spec.introduced:
        return False
    if spec.removed is not None and version >= spec.removed:
        return False
    return True

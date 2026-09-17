# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Stack-version feature gating for ES|QL commands and functions."""

from __future__ import annotations

from . import ast
from .errors import EsqlVersionError
from .features import ESQL_FEATURES, feature_available
from .utils import get_config_value
from .versions import Version

__all__ = ("verify_features",)

_COMMAND_FEATURE_MAP: dict[str, str] = {
    "fork": "fork",
    "join": "join",
    "completion": "completion",
    "grok": "grok",
    "dissect": "dissect",
    "enrich": "enrich",
    "mv_expand": "mv_expand",
    "rename": "rename",
    "lookup": "lookup",
    "promql": "promql",
}


def _command_feature_name(cmd: ast.Command) -> str | None:
    if isinstance(cmd, ast.StatsCommand) and cmd.inline:
        return "inline_stats"
    if isinstance(cmd, ast.FromCommand) and cmd.kind == "ts":
        return "time_series"
    if isinstance(cmd, ast.JoinCommand):
        return "lookup_join" if (cmd.kind or "").lower() == "lookup" else "join"
    mapping = {
        ast.ForkCommand: "fork",
        ast.CompletionCommand: "completion",
        ast.GrokCommand: "grok",
        ast.DissectCommand: "dissect",
        ast.EnrichCommand: "enrich",
        ast.MvExpandCommand: "mv_expand",
        ast.RenameCommand: "rename",
        ast.PromqlCommand: "promql",
        ast.ExplainCommand: "dev_explain",
        ast.ExternalCommand: "external_data_sources",
        ast.LookupCommand: "lookup",
    }
    for cls, name in mapping.items():
        if isinstance(cmd, cls):
            return name
    if isinstance(cmd, ast.GenericCommand):
        return _COMMAND_FEATURE_MAP.get(cmd.name.lower())
    return None


def verify_features(tree: ast.EsqlQuery, min_stack_version: str | Version | None = None) -> None:
    """Raise `EsqlVersionError` when the AST uses unavailable features."""
    version = min_stack_version or get_config_value("min_stack_version")
    if version is None:
        return
    text = str(version).strip().lower()
    if text in {"latest", "main", "master"}:
        # Tip grammar: treat as newer than any gated feature in the map.
        version_str = "99.0.0"
    else:
        version_str = str(Version.parse(version))
    overrides = get_config_value("features") or {}

    for cmd in tree.commands:
        feature = _command_feature_name(cmd)
        if feature is not None:
            enabled = overrides.get(feature)
            if enabled is None:
                enabled = feature_available(feature, version_str)
            if not enabled:
                spec = ESQL_FEATURES.get(feature)
                intro = spec.introduced if spec else Version(0, 0)
                raise EsqlVersionError(
                    f"Feature {feature!r} is not available for stack version {version_str} (introduced {intro})",
                    line=cmd.line or 0,
                    column=cmd.column or 0,
                    source=feature,
                )
        if isinstance(cmd, ast.FromCommand):
            for src in cmd.sources:
                if isinstance(src, ast.EsqlQuery):
                    verify_features(src, min_stack_version)
        elif isinstance(cmd, ast.ForkCommand):
            for branch in cmd.branches:
                verify_features(branch, min_stack_version)

    for node in tree:
        if isinstance(node, ast.FunctionCall):
            fname = node.name.lower()
            if fname not in {"kql", "eql"}:
                continue
            feature = f"{fname}_function"
            enabled = overrides.get(feature)
            if enabled is None:
                enabled = feature_available(feature, version_str)
            if not enabled:
                raise EsqlVersionError(
                    f"Function {fname.upper()}() is not available for stack version {version_str}",
                    line=node.line or 0,
                    column=node.column or 0,
                    source=fname,
                )

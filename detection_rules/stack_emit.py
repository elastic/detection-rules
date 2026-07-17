# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.
"""Stack-conditional emit transforms and version-lock emit epochs.

Emit transforms change the *shipped* rule payload for a package stack without
changing authored TOML baseline content. Version lock stack_emit records
emit epochs (not every minor stack) so Kibana can upgrade when shipped bytes
change on newer stacks while older stacks keep the baseline version.

Adding a future breaking change
--------------------------------
1. Define MIN_STACK = Version(X, Y, 0) (and any env/feature gates).
2. Implement _apply_<name>(obj, stack, context) -> None that mutates the
   API dict in place. Keep it idempotent and no-op when inapplicable.
3. Append an EmitTransform(...) to EMIT_TRANSFORMS with that apply fn.
4. Re-lock on the package branch that ships X.Y (manage_versions).

Do **not** add a stack_emit lock row per minor stack — only when the
applicable transform set changes (a new epoch). Call sites should go through
apply_emit_transforms; do not special-case new transforms in rule.py.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, cast

from semver import Version

from . import attack
from .config import (
    DEFAULT_THREAT_MAPPING_FRAMEWORK,
    DEFAULT_THREAT_MAPPING_VERSION,
    load_current_package_version,
)
from .integrations import RELATED_INTEGRATION_GTE_OPERATOR_ENV

# Re-export attack's gate so emit registry / callers share one constant.
MITRE_V19_MIN_STACK = attack.MITRE_V19_MIN_STACK
RELATED_INTEGRATIONS_GTE_MIN_STACK = Version(9, 5, 0)

EmitApplyFn = Callable[["dict[str, Any]", Version, "EmitContext"], None]


@dataclass
class EmitContext:
    """Optional inputs transforms may need that are not on the API payload.

    Extend this dataclass when a new transform needs repo-only data (e.g. fields
    stripped before emit). Avoid putting new special cases in rule.py.
    """

    threat_mappings: list[dict[str, Any]] | None = None
    extras: dict[str, Any] = field(default_factory=dict[str, Any])


@dataclass(frozen=True)
class EmitTransform:
    """A named, stack-gated packaging transform with an apply hook."""

    id: str
    min_stack: Version
    affects: tuple[str, ...]
    apply: EmitApplyFn


def _apply_mitre_attack_v19(obj: dict[str, Any], stack: Version, context: EmitContext) -> None:
    """Promote / convert threat (+ tactic tags) for stacks that ship ATT&CK v19."""
    # Pass stack so auto-promotion matches the transform registry gate, not a divergent
    # package-version lookup when apply_emit_transforms is called with an explicit stack.
    framework, version = attack.resolve_output_threat_version(stack)
    if framework == DEFAULT_THREAT_MAPPING_FRAMEWORK and str(version) == str(DEFAULT_THREAT_MAPPING_VERSION):
        return

    baseline_threat = list(obj.get("threat") or [])
    threat_mappings = context.threat_mappings

    selected: dict[str, Any] | None = next(
        (
            block
            for block in (threat_mappings or [])
            if block.get("framework") == framework and str(block.get("version")) == str(version)
        ),
        None,
    )
    if selected is not None:
        obj["threat"] = selected.get("threat", [])
    else:
        converted = attack.convert_threat_to_version(
            baseline_threat,
            source_version=DEFAULT_THREAT_MAPPING_VERSION,
            target_version=version,
            framework=framework,
        )
        if converted:
            obj["threat"] = converted

    if obj.get("threat") is not None:
        obj["tags"] = rewrite_tactic_tags(obj.get("tags"), baseline_threat, obj.get("threat"))


def _apply_related_integrations_gte(obj: dict[str, Any], stack: Version, context: EmitContext) -> None:
    """Rewrite related_integrations caret ranges to >= when the CI/package gate is on."""
    _ = context
    if stack < RELATED_INTEGRATIONS_GTE_MIN_STACK:
        return
    if os.getenv(RELATED_INTEGRATION_GTE_OPERATOR_ENV) != "True":
        return

    for entry in cast("list[dict[str, Any]]", obj.get("related_integrations") or []):
        version = entry.get("version")
        if isinstance(version, str) and version.startswith("^"):
            entry["version"] = f">={version[1:]}"


# Registry of value/field transforms. Append new breaking changes here.
# Lock epochs key off min_stack — do not add a row per package minor.
EMIT_TRANSFORMS: tuple[EmitTransform, ...] = (
    EmitTransform(
        id="mitre_attack_v19",
        min_stack=MITRE_V19_MIN_STACK,
        affects=("threat", "tags"),
        apply=_apply_mitre_attack_v19,
    ),
    EmitTransform(
        id="related_integrations_gte",
        min_stack=RELATED_INTEGRATIONS_GTE_MIN_STACK,
        affects=("related_integrations",),
        apply=_apply_related_integrations_gte,
    ),
)


def transforms_for_stack(stack: Version) -> list[EmitTransform]:
    """Return transforms whose min_stack is <= the package stack."""
    return [t for t in EMIT_TRANSFORMS if t.min_stack <= stack]


def emit_epoch_key(stack: Version) -> str | None:
    """Return the emit-epoch key for stack, or None when no transforms apply.

    The epoch is the newest transform min_stack among those applicable to
    stack (major.minor). Stacks that inherit the same transform set (e.g.
    9.6 with only 9.5 transforms) share the same epoch key and lock entry.
    """
    applicable = transforms_for_stack(stack)
    if not applicable:
        return None
    newest = max(t.min_stack for t in applicable)
    return f"{newest.major}.{newest.minor}"


def parse_stack(version: str | Version) -> Version:
    """Parse a stack version string or pass through a Version."""
    if isinstance(version, Version):
        return version
    return Version.parse(str(version), optional_minor_and_patch=True)


def apply_emit_transforms(
    obj: dict[str, Any],
    *,
    stack: Version | str | None = None,
    context: EmitContext | None = None,
) -> dict[str, Any]:
    """Apply all transforms for stack to obj in registry order (in place).

    This is the single extension point for stack-conditional payload changes.
    """
    stack_ver = parse_stack(stack if stack is not None else load_current_package_version())
    ctx = context or EmitContext()
    for transform in transforms_for_stack(stack_ver):
        transform.apply(obj, stack_ver, ctx)
    return obj


def resolve_stack_emit_entry(
    stack_emit: dict[str, dict[str, Any]] | None,
    package_stack: Version | str,
) -> dict[str, Any] | None:
    """Pick the highest stack_emit entry with key <= package_stack."""
    if not stack_emit:
        return None
    stack = parse_stack(package_stack)
    candidates: list[tuple[Version, dict[str, Any]]] = []
    for key, entry in stack_emit.items():
        key_ver = Version.parse(str(key), optional_minor_and_patch=True)
        if key_ver <= stack:
            candidates.append((key_ver, entry))
    if not candidates:
        return None
    return max(candidates, key=lambda item: item[0])[1]


def rewrite_tactic_tags(
    tags: list[str] | None,
    baseline_threat: list[dict[str, Any]] | None,
    emitted_threat: list[dict[str, Any]] | None,
) -> list[str]:
    """Replace baseline tactic tags with those implied by the emitted threat mapping."""
    tags = list(tags or [])
    baseline_names = {
        str(entry["tactic"]["name"])
        for entry in (baseline_threat or [])
        if isinstance(entry.get("tactic"), dict) and entry["tactic"].get("name")
    }
    emitted_names = {
        str(entry["tactic"]["name"])
        for entry in (emitted_threat or [])
        if isinstance(entry.get("tactic"), dict) and entry["tactic"].get("name")
    }

    kept: list[str] = []
    for tag in tags:
        if tag.startswith("Tactic: "):
            name = tag[len("Tactic: ") :]
            # Drop tactic tags that came from the baseline mapping and are gone after emit.
            if name in baseline_names and name not in emitted_names:
                continue
        kept.append(tag)

    for name in sorted(emitted_names):
        tag = f"Tactic: {name}"
        if tag not in kept:
            kept.append(tag)
    return kept

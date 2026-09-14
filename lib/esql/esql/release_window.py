# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Single source of truth for the detection-rules release-window grammar lines.

Edit `NUMBERED_LINES` / `TIP_LINE` / `WINDOW_REFS` here when the window changes.
Then run `make update-window` (sync + generate + check).
`tools/check_generated.py` enforces that provenances, registry, and `__es_compat__`
match this file — never hardcode the window elsewhere.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

from .versions import Version

__all__ = (
    "ReleaseLine",
    "NUMBERED_LINES",
    "TIP_LINE",
    "WINDOW_REFS",
    "all_lines",
    "all_stack_keys",
    "all_module_keys",
    "stack_to_module",
    "module_to_stack",
    "grammar_snapshots",
    "default_module",
    "tip_module",
    "format_es_compat",
    "read_module_provenance",
    "validate_window_refs",
)


@dataclass(frozen=True)
class ReleaseLine:
    """One vendored grammar line in the release window."""

    stack: str
    """Directory key under grammars/upstream|adapted (e.g. `9.4.0` or `latest`)."""

    module: str
    """Generated package under `esql._antlr` (e.g. `v9_4_0` or `vlatest`)."""

    major: int | None = None
    """Major for numbered floors; `None` for tip."""

    minor: int | None = None
    """Minor for numbered floors; `None` for tip."""

    @property
    def is_tip(self) -> bool:
        return self.major is None

    @property
    def floor(self) -> Version | None:
        if self.major is None or self.minor is None:
            return None
        return Version(self.major, self.minor)


# Ascending numbered release-window floors (edit when DR stack-schema-map changes).
NUMBERED_LINES: tuple[ReleaseLine, ...] = (
    ReleaseLine("8.19.0", "v8_19_0", 8, 19),
    ReleaseLine("9.3.0", "v9_3_0", 9, 3),
    ReleaseLine("9.4.0", "v9_4_0", 9, 4),
    ReleaseLine("9.5.0", "v9_5_0", 9, 5),
)

# Tip tracks Elasticsearch main for stacks beyond the newest numbered floor.
TIP_LINE = ReleaseLine("latest", "vlatest")

# ES git refs to sync per stack key. Bump when refreshing a line, then
# `make sync-grammar-window && make generate-grammar`. CI requires these
# to match committed `provenance.json` `elasticsearch_ref` values.
WINDOW_REFS: dict[str, str] = {
    "8.19.0": "v8.19.19",
    "9.3.0": "v9.3.8",
    "9.4.0": "v9.4.4",
    "9.5.0": "9.5",  # no GA tag yet — branch tip
    "latest": "main",
}


def all_lines() -> tuple[ReleaseLine, ...]:
    return (*NUMBERED_LINES, TIP_LINE)


def validate_window_refs() -> list[str]:
    """Return human-readable errors if WINDOW_REFS keys != release lines."""
    stacks = set(all_stack_keys())
    refs = set(WINDOW_REFS)
    errors: list[str] = []
    if missing := sorted(stacks - refs):
        errors.append(f"WINDOW_REFS missing stacks: {missing}")
    if extra := sorted(refs - stacks):
        errors.append(f"WINDOW_REFS has unknown stacks: {extra}")
    return errors


def all_stack_keys() -> list[str]:
    return [line.stack for line in all_lines()]


def all_module_keys() -> list[str]:
    return [line.module for line in all_lines()]


def stack_to_module() -> dict[str, str]:
    return {line.stack: line.module for line in all_lines()}


def module_to_stack() -> dict[str, str]:
    return {line.module: line.stack for line in all_lines()}


def grammar_snapshots() -> list[tuple[Version, str]]:
    return [(line.floor, line.module) for line in NUMBERED_LINES if line.floor is not None]


def default_module() -> str:
    """Newest numbered release-window module (not tip)."""
    return NUMBERED_LINES[-1].module


def tip_module() -> str:
    return TIP_LINE.module


def _package_root() -> Path:
    return Path(__file__).resolve().parent


def read_module_provenance(module: str) -> dict[str, Any]:
    """Load provenance.json for a generated ANTLR module."""
    # Prefer filesystem (editable / source tree); fall back to package resources.
    path = _package_root() / "_antlr" / module / "provenance.json"
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    try:
        ref = resources.files("esql._antlr").joinpath(module, "provenance.json")
        return json.loads(ref.read_text(encoding="utf-8"))
    except (FileNotFoundError, ModuleNotFoundError, TypeError, AttributeError) as exc:
        raise FileNotFoundError(f"missing provenance for module {module}") from exc


def _display_ref(ref: str) -> str:
    """Normalize ES git ref for the compact __es_compat__ string (strip leading `v`)."""
    if ref.startswith("v") and len(ref) > 1 and ref[1].isdigit():
        return ref[1:]
    return ref


@lru_cache(maxsize=1)
def format_es_compat() -> str:
    """Build `__es_compat__` from committed module provenances (window order)."""
    parts: list[str] = []
    for line in all_lines():
        prov = read_module_provenance(line.module)
        ref = prov.get("elasticsearch_ref")
        if not ref:
            raise ValueError(f"{line.module}/provenance.json missing elasticsearch_ref")
        parts.append(_display_ref(str(ref)))
    return "/".join(parts)

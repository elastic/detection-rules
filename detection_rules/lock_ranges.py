# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Which baseline entry and which stack_emit epochs serve a given stack in a version.lock entry.

A lock entry ships its top-level ``version`` to every stack unless the rule is forked, in which case older
stacks ship ``previous[<major.minor>]``. A ``stack_emit[<epoch>]`` row ships instead of the baseline on every
stack from the epoch key up to the next epoch key (9.6 inherits epoch 9.5 until a 9.6 epoch exists). The helpers
here map epochs to the baseline entries whose stack range they overlap, so a baseline is never moved onto, or
numbered below, a version one of its epochs has already shipped (issue #7012).
"""

from typing import Any, cast

from semver import Version

StackRange = tuple[Version | None, Version | None]  # [lower, upper), None = unbounded


def _stack(stack: str) -> Version:
    """Parse a major.minor lock key into a comparable Version."""
    return Version.parse(stack, optional_minor_and_patch=True)


def baseline_entry_for_stack(lock_entry: dict[str, Any], stripped_stack: str) -> tuple[dict[str, Any], str | None]:
    """Return the baseline entry that packages for ``stripped_stack`` ship, and the stack it is keyed on.

    A fork under ``previous`` is keyed on its stack. The top-level entry is keyed on its ``min_stack_version``
    only when the rule has forks; an unforked rule ships the top-level entry to every stack, so it is unkeyed.
    Mirrors VersionLock.get_locked_version.
    """
    previous = cast("dict[str, dict[str, Any]]", lock_entry.get("previous") or {})
    fork = previous.get(stripped_stack)
    if fork is not None:
        return fork, stripped_stack
    if previous and lock_entry.get("min_stack_version"):
        return lock_entry, str(lock_entry["min_stack_version"])
    return lock_entry, None


def entry_range(lock_entry: dict[str, Any], entry_stack: str | None) -> StackRange:
    """Stacks served by a baseline entry: from its key up to the next fork or top-level key."""
    if entry_stack is None:
        return None, None
    lower = _stack(entry_stack)
    boundaries: list[Version] = [_stack(s) for s in cast("dict[str, Any]", lock_entry.get("previous") or {})]
    if lock_entry.get("min_stack_version"):
        boundaries.append(_stack(str(lock_entry["min_stack_version"])))
    uppers = [b for b in boundaries if b > lower]
    return lower, (min(uppers) if uppers else None)


def epoch_range(lock_entry: dict[str, Any], epoch: str) -> StackRange:
    """Stacks served by an epoch: from its key up to the next epoch key (later stacks inherit it)."""
    lower = _stack(epoch)
    keys = [_stack(k) for k in cast("dict[str, Any]", lock_entry.get("stack_emit") or {})]
    uppers = [k for k in keys if k > lower]
    return lower, (min(uppers) if uppers else None)


def _overlaps(a: StackRange, b: StackRange) -> bool:
    a_lo, a_hi = a
    b_lo, b_hi = b
    starts_before_b_ends = b_hi is None or a_lo is None or a_lo < b_hi
    starts_before_a_ends = a_hi is None or b_lo is None or b_lo < a_hi
    return starts_before_b_ends and starts_before_a_ends


def epochs_for_baseline(
    lock_entry: dict[str, Any], entry_stack: str | None, exclude_epoch: str | None = None
) -> list[str]:
    """Epoch keys whose served stacks overlap the stacks served by the given baseline entry."""
    served = entry_range(lock_entry, entry_stack)
    return [
        epoch
        for epoch in cast("dict[str, Any]", lock_entry.get("stack_emit") or {})
        if epoch != exclude_epoch and _overlaps(epoch_range(lock_entry, epoch), served)
    ]


def emit_versions_for_baseline(
    lock_entry: dict[str, Any], entry_stack: str | None, exclude_epoch: str | None = None
) -> list[int]:
    """Versions shipped by the epochs that serve any stack the given baseline entry serves.

    ``exclude_epoch`` leaves one epoch out, for callers about to renumber it.
    """
    emit_entries = cast("dict[str, dict[str, Any]]", lock_entry.get("stack_emit") or {})
    return [
        int(emit_entries[epoch]["version"])
        for epoch in epochs_for_baseline(lock_entry, entry_stack, exclude_epoch)
        if emit_entries[epoch].get("version")
    ]


def floor_baseline_past_shipped(baseline_entry: dict[str, Any], shipped_versions: list[int], label: str = "") -> int:
    """Move a baseline past every version its epochs have shipped, so the number is never reused.

    Raises before touching the entry when a fork would leave its ``max_allowable_version`` range, which is
    reserved for the newer baseline; that fork then needs a wider buffer, not a silent collision.
    """
    current = int(baseline_entry["version"])
    if not shipped_versions or current > max(shipped_versions):
        return current
    floored = max(shipped_versions) + 1
    max_allowable = baseline_entry.get("max_allowable_version")
    if max_allowable is not None and floored > int(max_allowable):
        raise ValueError(
            f"Forked rule{': ' + label if label else ''}: dropping its emit epoch needs baseline {floored}, above "
            f"the fork's max allowable version {max_allowable}"
        )
    baseline_entry["version"] = floored
    return floored

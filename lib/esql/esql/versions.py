# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Stack version parsing helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Self

__all__ = ("Version", "parse_version", "compare_versions")

_VERSION_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?$")


@dataclass(frozen=True, order=True)
class Version:
    """Simple major.minor[.patch] version for feature gating."""

    major: int
    minor: int
    patch: int = 0

    @classmethod
    def parse(cls, value: str | Version | tuple[int, ...]) -> Version:
        if isinstance(value, Version):
            return value
        if isinstance(value, tuple):
            major, minor, *rest = value
            patch = rest[0] if rest else 0
            return cls(int(major), int(minor), int(patch))
        text = str(value).strip()
        match = _VERSION_RE.match(text)
        if not match:
            raise ValueError(f"Invalid version string: {value!r}")
        major, minor, patch = match.groups()
        return cls(int(major), int(minor), int(patch or 0))

    def __str__(self) -> str:
        if self.patch:
            return f"{self.major}.{self.minor}.{self.patch}"
        return f"{self.major}.{self.minor}"

    @classmethod
    def from_string(cls, value: str) -> Self:
        return cls.parse(value)


def parse_version(value: str | Version | tuple[int, ...]) -> Version:
    return Version.parse(value)


def compare_versions(left: str | Version, right: str | Version) -> int:
    """Return -1, 0, or 1 comparing two versions."""
    lval = Version.parse(left)
    rval = Version.parse(right)
    if lval < rval:
        return -1
    if lval > rval:
        return 1
    return 0

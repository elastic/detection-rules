# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Thread-local parser configuration context."""

from __future__ import annotations

import threading
from typing import Any

__all__ = (
    "ParserConfig",
    "get_config_value",
    "get_current_config",
)


class ParserConfig:
    """Context manager for parser / validator configuration."""

    __stacks = threading.local()

    def __init__(self, *managers: ParserConfig, **config: Any) -> None:
        self.managers = managers
        self.context = {k: v for k, v in config.items() if v is not None}

    @classmethod
    def get_stack(cls, name: str) -> list[Any]:
        return cls.__stacks.__dict__.setdefault(name, [])

    @classmethod
    def push_stack(cls, name: str, value: Any) -> None:
        cls.get_stack(name).append(value)

    @classmethod
    def pop_stack(cls, name: str) -> Any:
        return cls.get_stack(name).pop()

    @classmethod
    def read_stack(cls, name: str, default: Any = None, silent: bool = True) -> Any:
        stack = cls.get_stack(name)
        if silent and not stack:
            return default
        return stack[-1]

    def __enter__(self) -> ParserConfig:
        for mgr in self.managers:
            mgr.__enter__()
        for key, value in self.context.items():
            self.push_stack(key, value)
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        for key in self.context:
            self.pop_stack(key)
        for mgr in reversed(self.managers):
            mgr.__exit__(exc_type, exc_val, exc_tb)


def get_config_value(name: str, default: Any = None) -> Any:
    """Read a single value from the active ParserConfig context."""
    return ParserConfig.read_stack(name, default=default)


def get_current_config() -> dict[str, Any]:
    """Return merged view of all keys currently on the context stacks."""
    local = getattr(ParserConfig, "_ParserConfig__stacks", None)
    if local is None:
        return {}
    stacks = getattr(local, "__dict__", {})
    merged: dict[str, Any] = {}
    for name, stack in stacks.items():
        if stack:
            merged[name] = stack[-1]
    return merged

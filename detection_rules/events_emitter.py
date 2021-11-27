# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Functions for generating event documents that would trigger a given rule."""

import time
import random
import contextlib
from typing import List

from .ecs import get_schema, get_max_version
from .rule import AnyRuleData
from .utils import deep_merge
import detection_rules.fuzzylib as fuzzylib

__all__ = (
    "emit_events",
    "get_ast_stats",
)


class emitter:
    ecs_version = get_max_version()
    emitters = {}
    completeness_level = 0
    fuzziness = fuzzylib.fuzziness
    fuzzy_iter = fuzzylib.fuzzy_iter
    mappings_fields = set()

    def __init__(self, node_type):
        self.node_type = node_type
        self.successful = 0
        self.total = 0

    def __call__(self, func):
        if self.node_type in self.emitters:
            raise ValueError(f"Duplicate emitter for {self.node_type}: {func.__name__}")
        self.emitters[self.node_type] = self

        def wrapper(*args, **kwargs):
            self.total += 1
            ret = func(*args, **kwargs)
            self.successful += 1
            return ret

        self.wrapper = wrapper
        return wrapper

    @classmethod
    def add_mappings_field(cls, field):
        cls.mappings_fields.add(field)

    @classmethod
    def reset_mappings(cls):
        cls.mappings_fields = set()

    @classmethod
    def emit_events(cls, node):
        return cls.emitters[type(node)].wrapper(node)

    @classmethod
    def get_ast_stats(cls):
        return {k.__name__: (v.successful, v.total) for k,v in cls.emitters.items()}

    @classmethod
    def completeness(cls, level=None):
        if level is None:
            return cls.completeness_level
        @contextlib.contextmanager
        def _completeness(level):
            orig_level, cls.completeness_level = cls.completeness_level, level
            try:
                yield
            finally:
                cls.completeness_level = orig_level
        return _completeness(level)

    @classmethod
    def complete_iter(cls, iterable):
        max = 1 + round((len(iterable) - 1) * min(1, cls.completeness_level))
        return iterable[:max]

    @classmethod
    def iter(cls, iterable):
        return cls.complete_iter(cls.fuzzy_iter(iterable))

    @classmethod
    def emit_mappings(cls):
        mappings = {}
        for field in cls.mappings_fields:
            try:
                field_type = get_schema(version=cls.ecs_version)[field]["type"]
            except KeyError:
                field_type = "keyword"
            value = {"type": field_type}
            for part in reversed(field.split(".")):
                value = {"properties": {part: value}}
            deep_merge(mappings, value)
        return mappings


def emit_events(rule: AnyRuleData) -> List[str]:
    if rule.type not in ("query", "eql"):
        raise NotImplementedError(f"Unsupported rule type: {rule.type}")
    elif rule.language == "eql":
        docs = emitter.emit_events(rule.validator.ast)
    elif rule.language == "kuery":
        docs = emitter.emit_events(rule.validator.to_eql()) # shortcut?
    else:
        raise NotImplementedError(f"Unsupported query language: {rule.language}")

    emitter.add_mappings_field("@timestamp")
    emitter.add_mappings_field("ecs.version")
    emitter.add_mappings_field("rule.name")
    for doc in docs:
        doc.update({
            "@timestamp": int(time.time() * 1000),
            "ecs": {"version": emitter.ecs_version},
            "rule": {"name": rule.name},
        })
    return docs


def get_ast_stats():
    return emitter.get_ast_stats()


# circular dependency
import detection_rules.events_emitter_eql  # noqa: E402

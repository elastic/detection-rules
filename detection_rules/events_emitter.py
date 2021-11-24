# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Functions for generating event documents that would trigger a given rule."""

import time
from typing import List

from .rule import AnyRuleData
import detection_rules.fuzzylib as fuzzylib

__all__ = (
    "emit_events",
    "get_ast_stats",
)


class emitter:
    emitters = {}
    fuzziness = fuzzylib.fuzziness
    fuzzy_iter = fuzzylib.fuzzy_iter

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
    def emit_events(cls, node):
        return cls.emitters[type(node)].wrapper(node)

    @classmethod
    def get_ast_stats(cls):
        return {k.__name__: (v.successful, v.total) for k,v in cls.emitters.items()}


def emit_events(rule: AnyRuleData) -> List[str]:
    if rule.type not in ("query", "eql"):
        raise NotImplementedError(f"Unsupported rule type: {rule.type}")
    elif rule.language == "eql":
        docs = emitter.emit_events(rule.validator.ast)
    elif rule.language == "kuery":
        docs = emitter.emit_events(rule.validator.to_eql()) # shortcut?
    else:
        raise NotImplementedError(f"Unsupported query language: {rule.language}")

    for doc in docs:
        doc.update({
            "@timestamp": int(time.time() * 1000),
            "rule.name": rule.name,
        })
    return docs


def get_ast_stats():
    return emitter.get_ast_stats()


# circular dependency
import detection_rules.events_emitter_eql  # noqa: E402

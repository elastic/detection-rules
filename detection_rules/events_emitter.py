# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Functions for generating event documents that would trigger a given rule."""

import time
import random
from collections import namedtuple
from itertools import chain
from copy import deepcopy

from .utils import deep_merge, cached
from .events_emitter_eql import collect_constraints as collect_constraints_eql
from .events_emitter_eql import get_ast_stats  # noqa: F401

__all__ = (
    "SourceEvents",
)

default_custom_schema = {
    "file.Ext.windows.zone_identifier": {
        "type": "long",
    },
    "process.parent.Ext.real.pid": {
        "type": "long",
    },
}

QueryGuess = namedtuple("QueryGuess", ["query", "type", "language", "ast"])


def ast_from_eql_query(query):
    import eql
    with eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
        return eql.parse_query(query)


def ast_from_kql_query(query):
    import kql
    return kql.to_eql(query)  # shortcut?


@cached
def guess_from_query(query):
    exceptions = []
    try:
        return QueryGuess(query, "eql", "eql", ast_from_eql_query(query))
    except Exception as e:
        exceptions.append(("EQL", e))
    try:
        return QueryGuess(query, "query", "kuery", ast_from_kql_query(query))
    except Exception as e:
        exceptions.append(("Kuery", e))

    def rank(e):
        line = getattr(e[1], "line", -1)
        column = getattr(e[1], "column", -1)
        return (line, column)

    lang, error = sorted(exceptions, key=rank)[-1]
    raise ValueError(f"{lang} query error: {error}")


def ast_from_rule(rule):
    if rule.type not in ("query", "eql"):
        raise NotImplementedError(f"Unsupported rule type: {rule.type}")
    elif rule.language == "eql":
        return ast_from_eql_query(rule.query)
    elif rule.language == "kuery":
        return ast_from_kql_query(rule.query)
    else:
        raise NotImplementedError(f"Unsupported query language: {rule.language}")


def emit_mappings(fields, schema):
    mappings = {}
    for field in fields:
        try:
            field_type = schema[field]["type"]
        except KeyError:
            field_type = "keyword"
        value = {"type": field_type}
        for part in reversed(field.split(".")):
            value = {"properties": {part: value}}
        deep_merge(mappings, value)
    return mappings


def emit_field(field, value):
    for part in reversed(field.split(".")):
        value = {part: value}
    return value


def docs_from_branch(branch, schema, timestamp):
    docs = []
    for solution in branch.solve(schema):
        doc = {}
        for field, value in solution:
            if value is not None:
                deep_merge(doc, emit_field(field, value))
        if timestamp:
            deep_merge(doc, emit_field("@timestamp", timestamp[0]))
            timestamp[0] += 1
        docs.append(doc)
    return docs


def docs_from_root(root, schema, timestamp):
    return [docs_from_branch(branch, schema, timestamp) for branch in root]


def load_detection_rules_schema():
    from .ecs import get_schema, get_max_version

    ecs_version = get_max_version()
    ecs_schema = get_schema(version=ecs_version)
    custom_schema = deepcopy(default_custom_schema)
    return deep_merge(custom_schema, ecs_schema)


class SourceEvents:
    def __init__(self, schema=None):
        self.__roots = []
        self.schema = schema or {}

    @classmethod
    def from_ast(cls, ast):
        se = SourceEvents()
        se.add_ast(ast)
        return se

    @classmethod
    def from_query(cls, query):
        se = SourceEvents()
        se.add_query(query)
        return se

    @classmethod
    def from_rule(cls, rule):
        se = SourceEvents()
        se.add_rule(rule)
        return se

    def add_ast(self, ast):
        root = collect_constraints_eql(ast)
        self.try_emit(root)
        self.__roots.append(root)
        return root

    def add_query(self, query):
        ast = guess_from_query(query).ast
        return self.add_ast(ast)

    def add_rule(self, rule):
        ast = ast_from_rule(rule)
        return self.add_ast(ast)

    def fields(self):
        return set(chain(*(root.fields() for root in self.__roots)))

    def mappings(self, root=None):
        fields = self.fields() if root is None else root.fields()
        return emit_mappings(fields, self.schema)

    def roots(self):
        return iter(self.__roots)

    def emit(self, root=None, *, timestamp=True, complete=False, count=1):
        if timestamp:
            timestamp = [int(time.time() * 1000)]
        if not complete:
            branches = (random.choice(root or random.choice(self.__roots)) for _ in range(count))
            docs = (docs_from_branch(branch, self.schema, timestamp) for branch in branches)
        elif root is None:
            docs = (docs_from_root(root, self.schema, timestamp) for _ in range(count) for root in self.__roots)
        else:
            docs = (docs_from_root(root, self.schema, timestamp) for _ in range(count))
        return list(chain(*docs))

    def try_emit(self, root):
        state = random.getstate()
        try:
            _ = docs_from_root(root, self.schema, timestamp=False)
        finally:
            random.setstate(state)

    def __iter__(self):
        return self

    def __next__(self):
        return self.emit()

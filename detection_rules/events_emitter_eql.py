# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Functions for generating event documents that would trigger a given rule."""

import sys
import string
import random
import json
import copy
from typing import List
import eql

from .ecs import get_schema
from .utils import deep_merge
from .fuzzylib import *
from .events_emitter import emitter

__all__ = (
)

def emit(node: eql.ast.BaseNode) -> List[str]:
    return emitter.emit(node)

def is_field_array(name):
    try:
        return "array" in get_schema(version=emitter.ecs_version)[name]["normalize"]
    except KeyError:
        return False

@emitter(eql.ast.Field)
def emit_Field(node: eql.ast.Field, value):
    field = node.render()
    emitter.add_mappings_field(field)
    if is_field_array(field):
        value = [value]
    for part in reversed([node.base] + node.path):
        value = {part: value}
    return value

@emitter(eql.ast.Or)
def emit_Or(node: eql.ast.Or):
    docs = []
    for term in emitter.iter(node.terms):
        docs.extend(emit(term))
    return docs

@emitter(eql.ast.And)
def emit_And(node: eql.ast.And):
    docs = []
    for term in node.terms:
        term_docs = emit(term)
        if not docs:
            docs = term_docs
            continue
        new_docs = []
        for term_doc in term_docs:
            for doc in docs:
                new_docs.append(deep_merge(copy.deepcopy(doc), term_doc))
        docs = new_docs
    return docs

@emitter(eql.ast.Not)
def emit_Not(node: eql.ast.Not):
    if isinstance(node.term, eql.ast.InSet):
        return emit_InSet(node.term, negate=True)

    if isinstance(node.term, eql.ast.FunctionCall) and node.term.name == 'wildcard':
        if len(node.term.arguments) == 2 and isinstance(node.term.arguments[1], eql.ast.String):
            lhs, rhs = node.term.arguments
            return emit_Comparison(eql.ast.Comparison(lhs, eql.ast.Comparison.NE, rhs))

    raise NotImplementedError(f"Unsupported term negation: {type(node.term)}")

@emitter(eql.ast.InSet)
def emit_InSet(node: eql.ast.InSet, negate=False):
    if type(node.expression) != eql.ast.Field:
        raise NotImplementedError(f"Unsupported expression type: {type(node.expression)}")
    docs = []
    if negate:
        min_length = 3 * len(node.container)
        values = set(x.value for x in node.container)
        value = get_random_string(min_length, lambda x: x not in values)
        docs.append(emit_Field(node.expression, value))
    else:
        for term in emitter.iter(node.container):
            docs.append(emit_Field(node.expression, term.value))
    return docs

@emitter(eql.ast.Comparison)
def emit_Comparison(node: eql.ast.Comparison):
    ops = {
        eql.ast.String: {
            "==": lambda s: s,    "!=": lambda s: "!" + s,
        },
        eql.ast.Number: {
            "==": lambda n: n,    "!=": lambda n: n + 1,
            ">=": lambda n: n,    "<=": lambda n: n,
             ">": lambda n: n + 1, "<": lambda n: n - 1,
        },
        eql.ast.Boolean: {
            "==": lambda b: b,    "!=": lambda b: not b,
        }
    }

    if type(node.left) != eql.ast.Field:
        raise NotImplementedError(f"Unsupported LHS type: {type(node.left)}")
    if type(node.right) not in ops:
        raise NotImplementedError(f"Unsupported RHS type: {type(node.left)}")

    value = ops[type(node.right)][node.comparator](node.right.value)
    doc = emit_Field(node.left, value)
    return [doc]

@emitter(eql.ast.EventQuery)
def emit_EventQuery(node: eql.ast.EventQuery):
    if type(node.event_type) != str:
        raise NotImplementedError(f"Unsupported event_type type: {type(node.event_type)}")
    docs = emit(node.query)
    if node.event_type != "any":
        for doc in docs:
            emitter.add_mappings_field("event.category")
            deep_merge(doc, {"event": { "category": node.event_type }})
    return docs

@emitter(eql.ast.PipedQuery)
def emit_PipedQuery(node: eql.ast.PipedQuery):
    if node.pipes:
        raise NotImplementedError("Pipes are unsupported")
    return emit(node.first)

@emitter(eql.ast.SubqueryBy)
def emit_SubqueryBy(node: eql.ast.SubqueryBy):
    if any(not isinstance(value, eql.ast.Field) for value in node.join_values):
        raise NotImplementedError(f"Unsupported join values: {node.join_values}")
    if node.fork:
        raise NotImplementedError(f"Unsupported fork: {node.fork}")
    return (emit(node.query), node.join_values)

def lookup_Field(doc, field):
    for part in [field.base] + field.path:
        doc = doc[part]
    return doc

def lookup_join_value(idx, join_values, stack):
    if idx < len(join_values):
        return join_values[idx]
    doc, join_fields = stack[0]
    try:
        value = lookup_Field(doc, join_fields[idx])
    except KeyError:
        value = get_random_string(3 * len(join_fields))
    join_values.append(value)
    return value

def emit_JoinFields(doc, join_fields, join_values, stack):
    for i,field in enumerate(join_fields):
        value = lookup_join_value(i, join_values, stack)
        deep_merge(doc, emit_Field(field, value))
    return doc

def emit_Queries(queries, docs, stack):
    if queries:
        query_docs, join_fields = queries[0]
        for doc in query_docs:
            emit_Queries(queries[1:], docs, stack + [(doc, join_fields)])
    else:
        join_values = []
        for doc, join_fields in stack:
            docs.append(emit_JoinFields(copy.deepcopy(doc), join_fields, join_values, stack))
    return docs

@emitter(eql.ast.Sequence)
def emit_Sequence(node: eql.ast.Sequence):
    queries = [emit_SubqueryBy(query) for query in node.queries]
    if node.close:
        queries.append((emit(node.close), ()))
    return emit_Queries(queries, [], [])

@emitter(eql.ast.FunctionCall)
def emit_FunctionCall(node: eql.ast.FunctionCall):
    if node.name != "wildcard":
        raise NotImplementedError(f"Unsupported function: {node.name}")
    if type(node.arguments[0]) != eql.ast.Field:
        raise NotImplementedError(f"Unsupported argument type: {type(node.argument[0])}")
    if type(node.arguments[1]) != eql.ast.String:
        raise NotImplementedError(f"Unsupported argument type: {type(node.argument[1])}")
    docs = []
    for arg in emitter.iter(node.arguments[1:]):
        value = expand_wildcards(arg.value).lower()
        docs.append(emit_Field(node.arguments[0], value))
    return docs

@emitter(eql.ast.BaseNode)
@emitter(eql.ast.Expression)
@emitter(eql.ast.EqlNode)
@emitter(eql.ast.Literal)
@emitter(eql.ast.String)
@emitter(eql.ast.Number)
@emitter(eql.ast.Null)
@emitter(eql.ast.Boolean)
@emitter(eql.ast.TimeRange)
@emitter(eql.ast.TimeUnit)
@emitter(eql.ast.IsNotNull)
@emitter(eql.ast.IsNull)
@emitter(eql.ast.MathOperation)
@emitter(eql.ast.NamedSubquery)
@emitter(eql.ast.NamedParams)
@emitter(eql.ast.Join)
@emitter(eql.ast.PipeCommand)
@emitter(eql.ast.EqlAnalytic)
@emitter(eql.ast.Definition)
@emitter(eql.ast.BaseMacro)
@emitter(eql.ast.CustomMacro)
@emitter(eql.ast.Macro)
@emitter(eql.ast.Constant)
@emitter(eql.ast.PreProcessor)
def emit_not_implemented(node: eql.ast.BaseNode):
    sys.stderr.write(f"##### Emitter for {type(node)} is not implemented #####\n")
    sys.stderr.write(f"\n{node}\n")
    sys.stderr.write(f"\n{dir(node)}\n")
    sys.stderr.write(f"\nSlots:\n")
    for slot,value in node.iter_slots():
        sys.stderr.write(f"  {slot}: {value}\n")

    raise NotImplementedError(f"Emitter not implemented: {type(node)}")

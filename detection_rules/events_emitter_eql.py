# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Functions for generating event documents that would trigger a given rule."""

import string
import random
import json
import copy
import itertools
from typing import List, Tuple
import eql

from .utils import deep_merge
from .constraints import Constraints
from .fuzzylib import *
from .events_emitter import emitter

__all__ = (
)

def emit(node: eql.ast.BaseNode) -> List[Constraints]:
    return emitter.emit(node)

@emitter(eql.ast.Field)
def emit_Field(node: eql.ast.Field, value: str) -> Constraints:
    return Constraints(node.render(), "==", value)

@emitter(eql.ast.Boolean)
def emit_Boolean(node: eql.ast.Boolean):
    constraints = []
    if node.value:
        constraints.append(Constraints())
    return constraints

@emitter(eql.ast.Or)
def emit_Or(node: eql.ast.Or) -> List[Constraints]:
    constraints = []
    for term in emitter.iter(node.terms):
        constraints.extend(emit(term))
    return constraints

@emitter(eql.ast.And)
def emit_And(node: eql.ast.And) -> List[Constraints]:
    constraints = []
    for term in node.terms:
        term_constraints = emit(term)
        if constraints:
            constraints = [c + term_c for term_c in term_constraints for c in constraints]
        else:
            constraints = term_constraints
    return constraints

@emitter(eql.ast.Not)
def emit_Not(node: eql.ast.Not) -> List[Constraints]:
    if isinstance(node.term, eql.ast.InSet):
        return emit_InSet(node.term, negate=True)

    if isinstance(node.term, eql.ast.FunctionCall) and node.term.name == 'wildcard':
        if len(node.term.arguments) == 2 and isinstance(node.term.arguments[1], eql.ast.String):
            lhs, rhs = node.term.arguments
            return emit_Comparison(eql.ast.Comparison(lhs, eql.ast.Comparison.NE, rhs))

    raise NotImplementedError(f"Unsupported term negation: {type(node.term)}")

@emitter(eql.ast.InSet)
def emit_InSet(node: eql.ast.InSet, negate: bool=False) -> List[Constraints]:
    if type(node.expression) != eql.ast.Field:
        raise NotImplementedError(f"Unsupported expression type: {type(node.expression)}")
    constraints = []
    if negate:
        field = node.expression.render()
        c = Constraints()
        for term in node.container:
            c.append_constraint(field, "!=", term.value)
        constraints.append(c)
    else:
        for term in emitter.iter(node.container):
            constraints.append(emit_Field(node.expression, term.value))
    return constraints

@emitter(eql.ast.Comparison)
def emit_Comparison(node: eql.ast.Comparison) -> List[Constraints]:
    if type(node.left) != eql.ast.Field:
        raise NotImplementedError(f"Unsupported LHS type: {type(node.left)}")
    return [Constraints(node.left.render(), node.comparator, node.right.value)]

@emitter(eql.ast.EventQuery)
def emit_EventQuery(node: eql.ast.EventQuery) -> List[Constraints]:
    if type(node.event_type) != str:
        raise NotImplementedError(f"Unsupported event_type type: {type(node.event_type)}")
    constraints = emit(node.query)
    if node.event_type != "any":
        for c in constraints:
            c.append_constraint("event.category", "==", node.event_type)
    return constraints

@emitter(eql.ast.PipedQuery)
def emit_PipedQuery(node: eql.ast.PipedQuery) -> List[Constraints]:
    if node.pipes:
        raise NotImplementedError("Pipes are unsupported")
    return emit(node.first)

def emit_SubqueryBy(node: eql.ast.SubqueryBy) -> List[Tuple[Constraints,List[str]]]:
    if any(not isinstance(value, eql.ast.Field) for value in node.join_values):
        raise NotImplementedError(f"Unsupported join values: {node.join_values}")
    if node.fork:
        raise NotImplementedError(f"Unsupported fork: {node.fork}")
    join_fields = [field.render() for field in node.join_values]
    return [(c,join_fields) for c in emit(node.query)]

def emit_JoinSeq(seq: List[Tuple[Constraints,List[str]]]) -> List[Constraints]:
    constraints = []
    join_rows = []
    for c,join_fields in seq:
        c = c.clone()
        constraints.append(c)
        join_rows.append([(field,c) for field in join_fields])
    for join_col in zip(*join_rows):
        field0 = None
        for field,c in join_col:
            field0 = field0 or field
            constraints[0].append_constraint(field0, "join_value", (field,c))
    return constraints

@emitter(eql.ast.Sequence)
def emit_Sequence(node: eql.ast.Sequence) -> List[Constraints]:
    queries = [emit_SubqueryBy(query) for query in node.queries]
    if node.close:
        queries.append([(c,[]) for c in emit(node.close)])
    constraints = []
    for seq in itertools.chain(itertools.product(*queries)):
        constraints.extend(emit_JoinSeq(seq))
    return constraints

@emitter(eql.ast.FunctionCall)
def emit_FunctionCall(node: eql.ast.FunctionCall) -> List[Constraints]:
    if node.name != "wildcard":
        raise NotImplementedError(f"Unsupported function: {node.name}")
    if type(node.arguments[0]) != eql.ast.Field:
        raise NotImplementedError(f"Unsupported argument type: {type(node.argument[0])}")
    if type(node.arguments[1]) != eql.ast.String:
        raise NotImplementedError(f"Unsupported argument type: {type(node.argument[1])}")
    constraints = []
    for arg in emitter.iter(node.arguments[1:]):
        value = expand_wildcards(arg.value).lower()
        constraints.append(emit_Field(node.arguments[0], value))
    return constraints

@emitter(eql.ast.BaseNode)
@emitter(eql.ast.Expression)
@emitter(eql.ast.EqlNode)
@emitter(eql.ast.Literal)
@emitter(eql.ast.String)
@emitter(eql.ast.Number)
@emitter(eql.ast.Null)
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
def emit_not_implemented(node: eql.ast.BaseNode) -> List[Constraints]:
    raise NotImplementedError(f"Emitter not implemented: {type(node)}")

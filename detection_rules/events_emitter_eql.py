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
from typing import List, Tuple, Union
import eql

from .utils import deep_merge
from .constraints import Constraints
from .fuzzylib import *
from .events_emitter import emitter

__all__ = (
)

def emit(node: eql.ast.BaseNode, negate: bool) -> List[Constraints]:
    return emitter.emit(node, negate)

@emitter(eql.ast.Field)
def emit_Field(node: eql.ast.Field, value: str, negate: bool) -> Constraints:
    constraint_name = "!=" if negate else "=="
    return Constraints(node.render(), constraint_name, value)

@emitter(eql.ast.Boolean)
def emit_Boolean(node: eql.ast.Boolean, negate: bool):
    constraints = []
    if node.value if not negate else not node.value:
        constraints.append(Constraints())
    return constraints

def emit_OrTerms(node: Union[eql.ast.Or, eql.ast.And], negate: bool) -> List[Constraints]:
    constraints = []
    for term in emitter.iter(node.terms):
        constraints.extend(emit(term, negate))
    return constraints

def emit_AndTerms(node: Union[eql.ast.Or, eql.ast.And], negate: bool) -> List[Constraints]:
    constraints = []
    for term in node.terms:
        term_constraints = emit(term, negate)
        if constraints:
            constraints = [c + term_c for term_c in term_constraints for c in constraints]
        else:
            constraints = term_constraints
    return constraints

@emitter(eql.ast.Or)
def emit_Or(node: eql.ast.Or, negate: bool) -> List[Constraints]:
    if negate:
        return emit_AndTerms(node, negate)
    else:
        return emit_OrTerms(node, negate)

@emitter(eql.ast.And)
def emit_And(node: eql.ast.And, negate: bool) -> List[Constraints]:
    if negate:
        return emit_OrTerms(node, negate)
    else:
        return emit_AndTerms(node, negate)

@emitter(eql.ast.Not)
def emit_Not(node: eql.ast.Not, negate: bool) -> List[Constraints]:
    return emit(node.term, not negate)

@emitter(eql.ast.IsNull)
def emit_IsNull(node: eql.ast.IsNull, negate: bool) -> List[Constraints]:
    if type(node.expr) != eql.ast.Field:
        raise NotImplementedError(f"Unsupported expression type: {type(node.expr)}")
    constraint_name = "!=" if negate else "=="
    return [Constraints(node.expr.render(), constraint_name, None)]

@emitter(eql.ast.IsNotNull)
def emit_IsNotNull(node: eql.ast.IsNotNull, negate: bool) -> List[Constraints]:
    if type(node.expr) != eql.ast.Field:
        raise NotImplementedError(f"Unsupported expression type: {type(node.expr)}")
    constraint_name = "==" if negate else "!="
    return [Constraints(node.expr.render(), constraint_name, None)]

@emitter(eql.ast.InSet)
def emit_InSet(node: eql.ast.InSet, negate: bool) -> List[Constraints]:
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
            constraints.append(emit_Field(node.expression, term.value, negate))
    return constraints

@emitter(eql.ast.Comparison)
def emit_Comparison(node: eql.ast.Comparison, negate: bool) -> List[Constraints]:
    if type(node.left) != eql.ast.Field:
        raise NotImplementedError(f"Unsupported LHS type: {type(node.left)}")
    negation = {"==": "!=", "!=": "==", ">=": "<", "<=": ">", ">": "<=", "<": ">="}
    comparator = negation[node.comparator] if negate else node.comparator
    return [Constraints(node.left.render(), comparator, node.right.value)]

@emitter(eql.ast.EventQuery)
def emit_EventQuery(node: eql.ast.EventQuery, negate: bool) -> List[Constraints]:
    if negate:
        raise NotImplementedError(f"Negation of {type(node)} is not supported")
    if type(node.event_type) != str:
        raise NotImplementedError(f"Unsupported event_type type: {type(node.event_type)}")
    constraints = emit(node.query, negate)
    if node.event_type != "any":
        for c in constraints:
            c.append_constraint("event.category", "==", node.event_type)
    return constraints

@emitter(eql.ast.PipedQuery)
def emit_PipedQuery(node: eql.ast.PipedQuery, negate: bool) -> List[Constraints]:
    if negate:
        raise NotImplementedError(f"Negation of {type(node)} is not supported")
    if node.pipes:
        raise NotImplementedError("Pipes are unsupported")
    return emit(node.first, negate)

def emit_SubqueryBy(node: eql.ast.SubqueryBy, negate: bool) -> List[Tuple[Constraints, List[str]]]:
    if negate:
        raise NotImplementedError(f"Negation of {type(node)} is not supported")
    if any(not isinstance(value, eql.ast.Field) for value in node.join_values):
        raise NotImplementedError(f"Unsupported join values: {node.join_values}")
    if node.fork:
        raise NotImplementedError(f"Unsupported fork: {node.fork}")
    join_fields = [field.render() for field in node.join_values]
    return [(c,join_fields) for c in emit(node.query, negate)]

def emit_JoinSeq(seq: List[Tuple[Constraints, List[str]]]) -> List[Constraints]:
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
def emit_Sequence(node: eql.ast.Sequence, negate: bool) -> List[Constraints]:
    if negate:
        raise NotImplementedError(f"Negation of {type(node)} is not supported")
    queries = [emit_SubqueryBy(query, negate) for query in node.queries]
    if node.close:
        queries.append([(c,[]) for c in emit(node.close, negate)])
    constraints = []
    for seq in itertools.chain(itertools.product(*queries)):
        constraints.extend(emit_JoinSeq(seq))
    return constraints

@emitter(eql.ast.FunctionCall)
def emit_FunctionCall(node: eql.ast.FunctionCall, negate: bool) -> List[Constraints]:
    if type(node.arguments[0]) != eql.ast.Field:
        raise NotImplementedError(f"Unsupported argument type: {type(node.argument[0])}")
    if any(type(arg) != eql.ast.String for arg in node.arguments[1:]):
        raise NotImplementedError("Unsupported argument type(s): " +
            f"{', '.join(sorted({str(type(arg)) for arg in node.arguments[1:] if type(arg) != eql.ast.String}))}")
    fn_name = node.name.lower()
    if fn_name == "wildcard":
        return emit_FnConstraints(node, negate, "wildcard")
    elif fn_name == "cidrmatch":
        return emit_FnConstraints(node, negate, "in")
    else:
        raise NotImplementedError(f"Unsupported function: {node.name}")

def emit_FnConstraints(node: eql.ast.FunctionCall, negate: bool, constraint_name: str):
    field = node.arguments[0].render()
    constraint_name = f"not {constraint_name}" if negate else constraint_name
    c = Constraints(field, constraint_name, tuple(arg.value for arg in node.arguments[1:]))
    return [c]

@emitter(eql.ast.BaseNode)
@emitter(eql.ast.Expression)
@emitter(eql.ast.EqlNode)
@emitter(eql.ast.Literal)
@emitter(eql.ast.String)
@emitter(eql.ast.Number)
@emitter(eql.ast.Null)
@emitter(eql.ast.TimeRange)
@emitter(eql.ast.TimeUnit)
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
def emit_not_implemented(node: eql.ast.BaseNode, negate: bool) -> List[Constraints]:
    raise NotImplementedError(f"Emitter not implemented: {type(node)}")

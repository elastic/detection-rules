# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Functions for generating event documents that would trigger a given rule."""

import string
import random
import json
import copy
from itertools import chain, product
from typing import List, Tuple, Union, Any, NoReturn
import eql

from .utils import deep_merge, cached
from .constraints import Constraints, Branch, Root
from .events_emitter import emitter

__all__ = (
)

@cached
def _nope(operation: Any, negate: bool) -> Any:
    negation = {"==": "!=", "!=": "==", ">=": "<", "<=": ">", ">": "<=", "<": ">=",
        emit_OrTerms: emit_AndTerms, emit_AndTerms: emit_OrTerms}
    return operation if not negate else negation.get(operation, not operation)

def emit(node: eql.ast.BaseNode, negate: bool) -> Root:
    return emitter.emit(node, negate)

@emitter(eql.ast.Field)
def emit_Field(node: eql.ast.Field, value: str, negate: bool) -> Root:
    return Root([Branch([Constraints(node.render(), _nope("==", negate), value)])])

@emitter(eql.ast.Boolean)
def emit_Boolean(node: eql.ast.Boolean, negate: bool) -> Root:
    branches = []
    if _nope(node.value, negate):
        branches.append(Branch.Identity)
    return Root(branches)

def emit_OrTerms(node: Union[eql.ast.Or, eql.ast.And], negate: bool) -> Root:
    return Root.chain(emit(term, negate) for term in node.terms)

def emit_AndTerms(node: Union[eql.ast.Or, eql.ast.And], negate: bool) -> Root:
    return Root.product(emit(term, negate) for term in node.terms)

@emitter(eql.ast.Or)
def emit_Or(node: eql.ast.Or, negate: bool) -> Root:
    return _nope(emit_OrTerms, negate)(node, negate)

@emitter(eql.ast.And)
def emit_And(node: eql.ast.And, negate: bool) -> Root:
    return _nope(emit_AndTerms, negate)(node, negate)

@emitter(eql.ast.Not)
def emit_Not(node: eql.ast.Not, negate: bool) -> Root:
    return emit(node.term, not negate)

@emitter(eql.ast.IsNull)
def emit_IsNull(node: eql.ast.IsNull, negate: bool) -> Root:
    if type(node.expr) != eql.ast.Field:
        raise NotImplementedError(f"Unsupported expression type: {type(node.expr)}")
    return emit_Field(node.expr, None, negate)

@emitter(eql.ast.IsNotNull)
def emit_IsNotNull(node: eql.ast.IsNotNull, negate: bool) -> Root:
    if type(node.expr) != eql.ast.Field:
        raise NotImplementedError(f"Unsupported expression type: {type(node.expr)}")
    return emit_Field(node.expr, None, not negate)

@emitter(eql.ast.InSet)
def emit_InSet(node: eql.ast.InSet, negate: bool) -> Root:
    if type(node.expression) != eql.ast.Field:
        raise NotImplementedError(f"Unsupported expression type: {type(node.expression)}")
    branches = []
    if negate:
        field = node.expression.render()
        c = Constraints()
        for term in node.container:
            c.append_constraint(field, "!=", term.value)
        branches.append(Branch([c]))
    else:
        for term in node.container:
            branches.extend(emit_Field(node.expression, term.value, negate))
    return Root(branches)

@emitter(eql.ast.Comparison)
def emit_Comparison(node: eql.ast.Comparison, negate: bool) -> Root:
    if type(node.left) != eql.ast.Field:
        raise NotImplementedError(f"Unsupported LHS type: {type(node.left)}")
    return Root([Branch([Constraints(node.left.render(), _nope(node.comparator, negate), node.right.value)])])

@emitter(eql.ast.EventQuery)
def emit_EventQuery(node: eql.ast.EventQuery, negate: bool) -> Root:
    if negate:
        raise NotImplementedError(f"Negation of {type(node)} is not supported")
    if type(node.event_type) != str:
        raise NotImplementedError(f"Unsupported event_type type: {type(node.event_type)}")
    root = emit(node.query, negate)
    if node.event_type != "any":
        for c in root.constraints():
            c.append_constraint("event.category", "==", node.event_type)
    return root

@emitter(eql.ast.PipedQuery)
def emit_PipedQuery(node: eql.ast.PipedQuery, negate: bool) -> Root:
    if negate:
        raise NotImplementedError(f"Negation of {type(node)} is not supported")
    if node.pipes:
        raise NotImplementedError("Pipes are unsupported")
    return emit(node.first, negate)

def emit_SubqueryBy(node: eql.ast.SubqueryBy, negate: bool) -> List[Tuple[Constraints, List[str]]]:
    if negate:
        raise NotImplementedError(f"Negation of {type(node)} is not supported")
    if any(type(value) != eql.ast.Field for value in node.join_values):
        raise NotImplementedError(f"Unsupported join values: {node.join_values}")
    if node.fork:
        raise NotImplementedError(f"Unsupported fork: {node.fork}")
    join_fields = [field.render() for field in node.join_values]
    return [[(c,join_fields) for c in branch] for branch in emit(node.query, negate)]

def emit_JoinBranch(seq: List[Tuple[Constraints, List[str]]]) -> Branch:
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
    return Branch(constraints)

@emitter(eql.ast.Sequence)
def emit_Sequence(node: eql.ast.Sequence, negate: bool) -> Root:
    if negate:
        raise NotImplementedError(f"Negation of {type(node)} is not supported")
    queries = [emit_SubqueryBy(query, negate) for query in node.queries]
    if node.close:
        queries.append([[(c,[]) for c in branch] for branch in emit(node.close, negate)])
    return Root([emit_JoinBranch(chain(*branches)) for branches in chain(product(*queries))])

@emitter(eql.ast.FunctionCall)
def emit_FunctionCall(node: eql.ast.FunctionCall, negate: bool) -> Root:
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

def emit_FnConstraints(node: eql.ast.FunctionCall, negate: bool, constraint_name: str) -> Root:
    field = node.arguments[0].render()
    constraint_name = constraint_name if not negate else f"not {constraint_name}"
    c = Constraints(field, constraint_name, tuple(arg.value for arg in node.arguments[1:]))
    return Root([Branch([c])])

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
def emit_not_implemented(node: eql.ast.BaseNode, negate: bool) -> NoReturn:
    raise NotImplementedError(f"Emitter not implemented: {type(node)}")

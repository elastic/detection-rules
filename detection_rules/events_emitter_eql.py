# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Functions for collecting constraints from an EQL AST."""

import eql

from itertools import chain, product
from typing import List, Tuple, Union, Any, NoReturn

from .constraints import Constraints, Branch, Root
from .utils import TreeTraverser, cached

__all__ = ()

traverser = TreeTraverser()


def collect_constraints(node: eql.ast.BaseNode, negate: bool = False) -> Root:
    return traverser.traverse(node, negate)


def get_ast_stats():
    return traverser.get_stats()


@cached
def _nope(operation: Any, negate: bool) -> Any:
    negation = {"==": "!=", "!=": "==", ">=": "<", "<=": ">", ">": "<=", "<": ">=",
                cc_or_terms: cc_and_terms, cc_and_terms: cc_or_terms}
    return operation if not negate else negation.get(operation, not operation)


@traverser(eql.ast.Field)
def cc_field(node: eql.ast.Field, value: str, negate: bool) -> Root:
    c = Constraints(node.render(), _nope("==", negate), value)
    return Root([Branch([c])])


@traverser(eql.ast.Boolean)
def cc_boolean(node: eql.ast.Boolean, negate: bool) -> Root:
    branches = []
    if _nope(node.value, negate):
        branches.append(Branch.Identity)
    return Root(branches)


def cc_or_terms(node: Union[eql.ast.Or, eql.ast.And], negate: bool) -> Root:
    return Root.chain(collect_constraints(term, negate) for term in node.terms)


def cc_and_terms(node: Union[eql.ast.Or, eql.ast.And], negate: bool) -> Root:
    return Root.product(collect_constraints(term, negate) for term in node.terms)


@traverser(eql.ast.Or)
def cc_or(node: eql.ast.Or, negate: bool) -> Root:
    return _nope(cc_or_terms, negate)(node, negate)


@traverser(eql.ast.And)
def cc_and(node: eql.ast.And, negate: bool) -> Root:
    return _nope(cc_and_terms, negate)(node, negate)


@traverser(eql.ast.Not)
def cc_not(node: eql.ast.Not, negate: bool) -> Root:
    return collect_constraints(node.term, not negate)


@traverser(eql.ast.IsNull)
def cc_is_null(node: eql.ast.IsNull, negate: bool) -> Root:
    if type(node.expr) != eql.ast.Field:
        raise NotImplementedError(f"Unsupported expression type: {type(node.expr)}")
    return cc_field(node.expr, None, negate)


@traverser(eql.ast.IsNotNull)
def cc_is_not_null(node: eql.ast.IsNotNull, negate: bool) -> Root:
    if type(node.expr) != eql.ast.Field:
        raise NotImplementedError(f"Unsupported expression type: {type(node.expr)}")
    return cc_field(node.expr, None, not negate)


@traverser(eql.ast.InSet)
def cc_in_set(node: eql.ast.InSet, negate: bool) -> Root:
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
            branches.extend(cc_field(node.expression, term.value, negate))
    return Root(branches)


@traverser(eql.ast.Comparison)
def cc_comparison(node: eql.ast.Comparison, negate: bool) -> Root:
    if type(node.left) != eql.ast.Field:
        raise NotImplementedError(f"Unsupported LHS type: {type(node.left)}")
    c = Constraints(node.left.render(), _nope(node.comparator, negate), node.right.value)
    return Root([Branch([c])])


@traverser(eql.ast.EventQuery)
def cc_event_query(node: eql.ast.EventQuery, negate: bool) -> Root:
    if negate:
        raise NotImplementedError(f"Negation of {type(node)} is not supported")
    if type(node.event_type) != str:
        raise NotImplementedError(f"Unsupported event_type type: {type(node.event_type)}")
    root = collect_constraints(node.query, negate)
    if node.event_type != "any":
        for c in root.constraints():
            c.append_constraint("event.category", "==", node.event_type)
    return root


@traverser(eql.ast.PipedQuery)
def cc_piped_query(node: eql.ast.PipedQuery, negate: bool) -> Root:
    if negate:
        raise NotImplementedError(f"Negation of {type(node)} is not supported")
    if node.pipes:
        raise NotImplementedError("Pipes are unsupported")
    return collect_constraints(node.first, negate)


def cc_subquery_by(node: eql.ast.SubqueryBy, negate: bool) -> List[Tuple[Constraints, List[str]]]:
    if negate:
        raise NotImplementedError(f"Negation of {type(node)} is not supported")
    if any(type(value) != eql.ast.Field for value in node.join_values):
        raise NotImplementedError(f"Unsupported join values: {node.join_values}")
    if node.fork:
        raise NotImplementedError(f"Unsupported fork: {node.fork}")
    join_fields = [field.render() for field in node.join_values]
    return [[(c, join_fields) for c in branch] for branch in collect_constraints(node.query, negate)]


def cc_join_branch(seq: List[Tuple[Constraints, List[str]]]) -> Branch:
    constraints = []
    join_rows = []
    for c, join_fields in seq:
        c = c.clone()
        constraints.append(c)
        join_rows.append([(field, c) for field in join_fields])
    for join_col in zip(*join_rows):
        field0 = None
        for field, c in join_col:
            field0 = field0 or field
            constraints[0].append_constraint(field0, "join_value", (field, c))
    return Branch(constraints)


@traverser(eql.ast.Sequence)
def cc_sequence(node: eql.ast.Sequence, negate: bool) -> Root:
    if negate:
        raise NotImplementedError(f"Negation of {type(node)} is not supported")
    queries = [cc_subquery_by(query, negate) for query in node.queries]
    if node.close:
        queries.append([[(c, []) for c in branch] for branch in collect_constraints(node.close, negate)])
    return Root([cc_join_branch(chain(*branches)) for branches in chain(product(*queries))])


@traverser(eql.ast.FunctionCall)
def cc_function_call(node: eql.ast.FunctionCall, negate: bool) -> Root:
    if type(node.arguments[0]) != eql.ast.Field:
        raise NotImplementedError(f"Unsupported argument type: {type(node.argument[0])}")
    if any(type(arg) != eql.ast.String for arg in node.arguments[1:]):
        non_string_args = sorted({str(type(arg)) for arg in node.arguments[1:] if type(arg) != eql.ast.String})
        raise NotImplementedError(f"Unsupported argument type(s): {', '.join(non_string_args)}")
    fn_name = node.name.lower()
    if fn_name == "wildcard":
        return cc_function(node, negate, "wildcard")
    elif fn_name == "cidrmatch":
        return cc_function(node, negate, "in")
    else:
        raise NotImplementedError(f"Unsupported function: {node.name}")


def cc_function(node: eql.ast.FunctionCall, negate: bool, constraint_name: str) -> Root:
    field = node.arguments[0].render()
    constraint_name = constraint_name if not negate else f"not {constraint_name}"
    c = Constraints(field, constraint_name, tuple(arg.value for arg in node.arguments[1:]))
    return Root([Branch([c])])


@traverser(eql.ast.BaseNode)
@traverser(eql.ast.Expression)
@traverser(eql.ast.EqlNode)
@traverser(eql.ast.Literal)
@traverser(eql.ast.String)
@traverser(eql.ast.Number)
@traverser(eql.ast.Null)
@traverser(eql.ast.TimeRange)
@traverser(eql.ast.TimeUnit)
@traverser(eql.ast.MathOperation)
@traverser(eql.ast.NamedSubquery)
@traverser(eql.ast.NamedParams)
@traverser(eql.ast.Join)
@traverser(eql.ast.PipeCommand)
@traverser(eql.ast.EqlAnalytic)
@traverser(eql.ast.Definition)
@traverser(eql.ast.BaseMacro)
@traverser(eql.ast.CustomMacro)
@traverser(eql.ast.Macro)
@traverser(eql.ast.Constant)
@traverser(eql.ast.PreProcessor)
def cc_not_implemented(node: eql.ast.BaseNode, negate: bool) -> NoReturn:
    raise NotImplementedError(f"Traverser not implemented: {type(node)}")

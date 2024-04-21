# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import eql
from eql import DepthFirstWalker

from .ast import (
    Value, String, OrValues, Field, Expression, FieldRange, FieldComparison,
    NotExpr, AndExpr, OrExpr, Exists, Wildcard
)


class Eql2Kql(DepthFirstWalker):

    def _walk_default(self, tree, *args, **kwargs):
        if isinstance(tree, eql.ast.EqlNode):
            raise eql.errors.EqlCompileError("Unable to convert {}".format(tree))
        else:
            return tree

    def check_field_expression(self, tree):
        if not isinstance(tree, Expression):
            raise eql.errors.EqlCompileError("Expected expression, but got {}".format(repr(tree)))
        return tree

    def check_field_expressions(self, trees):
        for tree in trees:
            self.check_field_expression(tree)
        return trees

    def _walk_and(self, tree):  # type: (eql.ast.And) -> AndExpr
        return AndExpr(self.check_field_expressions(tree.terms))

    def _walk_or(self, tree):  # type: (eql.ast.Or) -> OrExpr
        return OrExpr(self.check_field_expressions(tree.terms))

    def _walk_not(self, tree):  # type: (eql.ast.Not) -> NotExpr
        return NotExpr(self.check_field_expression(tree.term))

    def _walk_is_null(self, node):  # type: (eql.ast.IsNull) -> FieldComparison
        if not isinstance(node.expr, Field):
            raise eql.errors.EqlCompileError("Unable to compare a non-field [{}] to null".format(node.expr))

        return NotExpr(FieldComparison(node.expr, Exists()))

    def _walk_is_not_null(self, node):  # type: (eql.ast.IsNotNull) -> Expression
        if not isinstance(node.expr, Field):
            raise eql.errors.EqlCompileError("Unable to compare a non-field [{}] to null".format(node.expr))

        return FieldComparison(node.expr, Exists())

    def _walk_field(self, tree):  # type: (eql.ast.Field) -> Field
        if any(eql.utils.is_number(n) for n in tree.path):
            raise eql.errors.EqlCompileError("Unable to convert array field: {}".format(tree))

        return Field(tree.render())

    def _walk_in_set(self, tree):  # type: (eql.ast.InSet) -> FieldComparison
        if not isinstance(tree.expression, Field) or not all(isinstance(v, Value) for v in tree.container):
            raise eql.errors.EqlCompileError("Unable to convert `{}`".format(tree.expression, tree))

        return FieldComparison(tree.expression, OrValues(tree.container))

    def _walk_function_call(self, tree):  # type: (eql.ast.FunctionCall) -> KqlNode
        if tree.name in ("wildcard", "cidrMatch"):
            if isinstance(tree.arguments[0], Field):
                if tree.name == "wildcard":
                    args = []
                    for arg in tree.arguments[1:]:
                        if '*' in arg.value or '?' in arg.value:
                            args.append(Wildcard(arg.value))
                        else:
                            args.append(arg)
                    return FieldComparison(tree.arguments[0], OrValues(args))
                else:
                    return FieldComparison(tree.arguments[0], OrValues(tree.arguments[1:]))
        raise eql.errors.EqlCompileError("Unable to convert `{}`".format(tree))

    def _walk_literal(self, tree):
        return Value.from_python(tree.value)

    def _walk_event_query(self, tree):  # type: (eql.ast.EventQuery) -> KqlNode
        if tree.event_type == eql.schema.EVENT_TYPE_ANY:
            return self.check_field_expression(tree.query)

        event_check = FieldComparison(Field("event.category"), String(tree.event_type))

        # for `x where true` shorthand, drop the `where true`
        if tree.query == Value.from_python(True):
            return event_check

        self.check_field_expression(tree.query)
        return AndExpr([event_check, tree.query])

    def _walk_filter_pipe(self, tree):  # type: (eql.pipes.FilterPipe) -> KqlNode
        return self.check_field_expression(tree.expression)

    def _walk_piped_query(self, tree):  # type: (eql.ast.PipedQuery) -> KqlNode
        if not tree.pipes:
            return tree.first

        return AndExpr([tree.first] + tree.pipes)

    LT, LE, EQ, NE, GE, GT = ('<', '<=', '==', '!=', '>=', '>')
    flipped = {LT: GE, LE: GT,
               EQ: EQ, NE: NE,
               GE: LT, GT: LE}

    def _walk_comparison(self, tree):  # type: (eql.ast.Comparison) -> KqlNode
        left = tree.left
        op = tree.comparator
        right = tree.right

        # move the literal to the right
        if isinstance(left, eql.ast.Literal):
            left, right = right, left
            op = self.flipped[op]

        if isinstance(left, Field) and isinstance(right, Value):
            if op == eql.ast.Comparison.EQ:
                return FieldComparison(left, right)
            elif op == eql.ast.Comparison.NE:
                return NotExpr(FieldComparison(left, right))
            else:
                return FieldRange(left, op, right)

        raise eql.errors.EqlCompileError("Unable to convert {}".format(tree))

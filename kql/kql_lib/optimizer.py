# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import functools

from eql import Walker, DepthFirstWalker

from .ast import AndValues, NotValue, Value, OrValues, NotExpr, FieldComparison


class Optimizer(DepthFirstWalker):

    def flat_optimize(self, tree):
        return Walker.walk(self, tree)

    def _walk_default(self, tree, *args, **kwargs):
        return tree

    def group_fields(self, tree, value_cls):  # type: (List, type) -> KqlNode
        cls = type(tree)
        field_groups = {}
        ungrouped = []

        for term in tree.items:
            # move a `not` inwards before grouping
            if isinstance(term, NotExpr) and isinstance(term.expr, FieldComparison):
                term = FieldComparison(term.expr.field, NotValue(term.expr.value))

            if isinstance(term, FieldComparison):
                if term.field.name in field_groups:
                    existing_checks = field_groups[term.field.name]
                    existing_checks.append(term)
                    continue
                else:
                    field_groups[term.field.name] = [term]

            ungrouped.append(term)

        for term in ungrouped:
            if isinstance(term, FieldComparison):
                term.value = self.flat_optimize(value_cls([t.value for t in field_groups[term.field.name]]))

        ungrouped = [self.flat_optimize(u) for u in ungrouped]
        return cls(ungrouped) if len(ungrouped) > 1 else ungrouped[0]

    @staticmethod
    def sort_key(a, b):
        if isinstance(a, Value) and not isinstance(b, Value):
            return -1
        if not isinstance(a, Value) and isinstance(b, Value):
            return +1

        if isinstance(a, Value) and isinstance(b, Value):
            t_a = type(a)
            t_b = type(b)

            if t_a == t_b:
                return (a.value > b.value) - (a.value < b.value)
            else:
                return (t_a.__name__ > t_b.__name__) - (t_a.__name__ < t_b.__name__)

        else:
            # unable to compare
            return 0

    def _walk_field_comparison(self, tree):  # type: (FieldComparison) -> KqlNode
        # if there's a single `not`, then pull it out of the expression
        if isinstance(tree.value, NotValue):
            return NotExpr(FieldComparison(tree.field, tree.value.value))
        return tree

    def flatten(self, tree):  # type: (List) -> List
        cls = type(tree)
        flattened = []
        for node in tree.items:
            if isinstance(node, cls):
                flattened.extend(node.items)
            else:
                flattened.append(node)

        flattened = [self.flat_optimize(t) for t in flattened]
        return cls(flattened)

    def flatten_values(self, tree, dual_cls):  # type: (List, type) -> List
        cls = type(tree)
        flattened = []
        not_term = None

        for term in self.flatten(tree).items:
            if isinstance(term, NotValue) and isinstance(term.value, Value):
                # create a copy to leave the source tree unaltered
                term = NotValue(term.value)
                if not_term is None:
                    not_term = term
                else:
                    not_term.value = dual_cls([not_term.value, term.value])
                    continue

            flattened.append(term)

        if not_term is not None:
            not_term.value = self.flat_optimize(not_term.value)

        flattened = [self.flat_optimize(t) for t in flattened]
        flattened.sort(key=functools.cmp_to_key(self.sort_key))
        return cls(flattened) if len(flattened) > 1 else flattened[0]

    def _walk_not_value(self, tree):  # type: (NotValue) -> KqlNode
        if isinstance(tree.value, NotValue):
            return tree.value.value
        return tree

    def _walk_or_values(self, tree):
        return self.flatten_values(tree, AndValues)

    def _walk_and_values(self, tree):
        return self.flatten_values(tree, OrValues)

    def _walk_not_expr(self, tree):  # type: (NotExpr) -> KqlNode
        if isinstance(tree.expr, NotExpr):
            return tree.expr.expr
        return tree

    def _walk_and_expr(self, tree):  # type: (AndExpr) -> KqlNode
        return self.group_fields(self.flatten(tree), value_cls=AndValues)

    def _walk_or_expr(self, tree):  # type: (OrExpr) -> KqlNode
        return self.group_fields(self.flatten(tree), value_cls=OrValues)

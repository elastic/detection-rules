# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from collections import defaultdict
from eql import Walker
from .errors import KqlCompileError


def boolean(**kwargs):
    """Wrap a query in a boolean term and optimize while building."""
    assert len(kwargs) == 1
    [(boolean_type, children)] = kwargs.items()

    if not isinstance(children, list):
        children = [children]

    dsl = defaultdict(list)

    if boolean_type in ("must", "filter"):
        # safe to convert and(and(x), y) -> and(x, y)
        for child in children:
            if list(child) == ["bool"]:
                for child_type, child_terms in child["bool"].items():
                    if child_type in ("must", "filter"):
                        dsl[child_type].extend(child_terms)
                    elif child_type == "should":
                        if "should" not in dsl:
                            dsl[child_type].extend(child_terms)
                        else:
                            dsl[boolean_type].append(boolean(should=child_terms))
                    elif child_type == "must_not":
                        dsl[child_type].extend(child_terms)
                    elif child_type != "minimum_should_match":
                        raise ValueError("Unknown term {}: {}".format(child_type, child_terms))
            else:
                dsl[boolean_type].append(child)

    elif boolean_type == "should":
        # can flatten `should` of `should`
        for child in children:
            if list(child) == ["bool"] and set(child["bool"]).issubset({"should", "minimum_should_match"}):
                dsl["should"].extend(child["bool"]["should"])
            else:
                dsl[boolean_type].append(child)

    elif boolean_type == "must_not" and len(children) == 1:
        # must_not: [{bool: {must: x}}] -> {must_not: x}
        # optimize can only occur with one term
        # e.g. the following would not be valid
        # must_not: [{bool: {must: x} and {bool: {must: y} }] -> {must_not: x} {must_not: y}
        child = children[0]
        is_bool = list(child) == ["bool"]
        bool_keys = list(child.get("bool", {}))
        has_valid_keys = bool_keys in (["filter"], ["must"])
        has_single_filter = len(child.get("bool", {}).get("filter", [])) == 1
        has_single_must = len(child.get("bool", {}).get("must", [])) == 1

        if is_bool and has_valid_keys and (has_single_filter or has_single_must):
            (negated,) = child["bool"].values()
            dsl = {"must_not": negated}
        else:
            dsl = {"must_not": children}

    else:
        dsl = dict(kwargs)

    if "should" in dsl:
        dsl.update(minimum_should_match=1)

    dsl = {"bool": dict(dsl)}
    return dsl


class ToDsl(Walker):
    def _walk_default(self, node, *args, **kwargs):
        raise KqlCompileError("Unable to convert {}".format(node))

    def _walk_exists(self, _):
        return lambda field: {"exists": {"field": field}}

    def _walk_wildcard(self, tree):
        return lambda field: {"query_string": {"fields": [field], "query": tree.value}}

    def _walk_value(self, tree):
        return lambda field: {"match": {field: tree.value}}

    def _walk_field(self, field):
        return field.name

    def _walk_field_range(self, tree):
        operator_map = {"<": "lt", "<=": "lte", ">=": "gte", ">": "gt"}
        field = self.walk(tree.field)
        return {"range": {field: {operator_map[tree.operator]: tree.value.value}}}

    def _walk_not_expr(self, tree):
        return boolean(must_not=[self.walk(tree.expr)])

    def _walk_and_expr(self, tree):
        return boolean(filter=[self.walk(node) for node in tree.items])

    def _walk_or_expr(self, tree):
        return boolean(should=[self.walk(node) for node in tree.items])

    def _walk_and_values(self, tree):
        children = [self.walk(node) for node in tree.items]
        return lambda field: boolean(filter=[child(field) for child in children])

    def _walk_or_values(self, tree):
        children = [self.walk(node) for node in tree.items]
        return lambda field: boolean(should=[child(field) for child in children])

    def _walk_not_value(self, tree):
        child = self.walk(tree.value)
        return lambda field: boolean(must_not=[child(field)])

    def _walk_field_comparison(self, tree):
        field = self.walk(tree.field)
        value_fn = self.walk(tree.value)

        return value_fn(field)

    @classmethod
    def convert(cls, tree):
        return boolean(filter=[cls().walk(tree)])

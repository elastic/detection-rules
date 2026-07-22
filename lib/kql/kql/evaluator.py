# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import operator
import re

import eql.ast
from eql import Walker, EqlCompileError, utils
from eql.functions import CidrMatch
from .ast import Wildcard
from .errors import KqlRuntimeError, KqlCompileError
from .parser import is_ipaddress

class FilterGenerator(Walker):
    __cidr_cache = {}

    def _walk_default(self, node, *args, **kwargs):
        raise KqlCompileError("Unable to convert {}".format(node))

    @classmethod
    def equals(cls, term, value):
        """Check if a term is equal to a value."""
        if utils.is_string(term) and utils.is_string(value):
            if is_ipaddress(term) and eql.utils.is_cidr_pattern(value):
                # check for an ipv4 cidr
                if value not in cls.__cidr_cache:
                    cls.__cidr_cache[value] = CidrMatch.get_callback(None, eql.ast.String(value))
                return cls.__cidr_cache[value](term)

        return term == value

    @classmethod
    def get_terms(cls, document, path):
        if isinstance(document, (tuple, list)):
            for d in document:
                for term in cls.get_terms(d, path):
                    yield term

        elif isinstance(document, dict):
            document = document.get(path[0])
            path = path[1:]

            if len(path) > 0:
                for term in cls.get_terms(document, path):
                    yield term
            elif isinstance(document, (tuple, list)):
                for term in document:
                    yield term
            elif document is not None:
                yield document

    def _walk_value(self, tree, compare_function=None):
        value = tree.value
        compare_function = compare_function or self.equals

        def check_value(term):
            if term is None:
                return False

            if isinstance(term, list):
                return any(check_value(t) for t in term)

            if isinstance(term, (bool, float, int)) or utils.is_string(term):
                v = value

                if utils.is_string(v) and isinstance(term, (bool, int, float)):
                    if isinstance(term, bool):
                        # only the literal true/false can match a boolean term
                        if v not in ("true", "false"):
                            return False
                        v = v == "true"
                    else:
                        try:
                            v = float(v) if isinstance(term, float) else int(v)
                        except ValueError:
                            # the string can't coerce to the term's type, so it can never
                            # match (mirrors Elasticsearch's lenient behavior)
                            return False

                elif utils.is_string(term) and isinstance(v, (bool, int, float)):
                    v = utils.to_unicode(v)

                return compare_function(term, v)
            else:
                raise KqlRuntimeError("Cannot compare value {}".format(term))

        return check_value

    def _walk_exists(self, _):
        return lambda terms: any(t is not None for t in terms)

    def _walk_wildcard(self, tree):
        pattern = tree.value
        regex = re.compile(".*?".join(map(re.escape, pattern.split("*"))), re.UNICODE | re.DOTALL)
        return lambda terms: any(t is not None and regex.fullmatch(t) for t in terms)

    def _walk_field(self, field):
        path = field.name.split(".")
        get_terms = self.get_terms

        def callback(document):
            terms = get_terms(document, path)
            terms = list(terms)
            return terms

        return callback

    @classmethod
    def get_all_terms(cls, document):
        """Yield every leaf value in the document, for values searched without a field."""
        if isinstance(document, (tuple, list)):
            for item in document:
                for term in cls.get_all_terms(item):
                    yield term
        elif isinstance(document, dict):
            for item in document.values():
                for term in cls.get_all_terms(item):
                    yield term
        elif document is not None:
            yield document

    def _walk_free_text(self, tree):
        check = self.walk(tree.value)
        get_all_terms = self.get_all_terms
        # wildcard matching only applies to strings; other leaf values can never match
        strings_only = isinstance(tree.value, Wildcard)

        def callback(document):
            terms = list(get_all_terms(document))
            if strings_only:
                terms = [term for term in terms if utils.is_string(term)]
            return check(terms)

        return callback

    def _walk_field_range(self, tree):
        field = self.walk(tree.field)
        operators = {"<": operator.lt, "<=": operator.le, ">=": operator.ge, ">": operator.gt}

        check_range = self.walk(tree.value, operators[tree.operator])
        return lambda doc: check_range(field(doc))

    def _walk_nested_query(self, tree):
        field = self.walk(tree.field)
        expr = self.walk(tree.expr)

        def check_nested(doc):
            doc = field(doc)

            if isinstance(doc, dict):
                return expr(doc)
            elif isinstance(doc, (list, tuple)):
                return any(expr(d) for d in doc)

        return check_nested

    def _walk_list(self, trees, reduce_function, *args, **kwargs):
        walked = [self.walk(item, *args, **kwargs) for item in trees.items]
        return lambda x: reduce_function(item(x) for item in walked)

    def _walk_not_expr(self, tree):
        expr = self.walk(tree.expr)
        return lambda doc: not expr(doc)

    def _walk_and_expr(self, tree):
        return self._walk_list(tree, all)

    def _walk_or_expr(self, tree):
        return self._walk_list(tree, any)

    def _walk_and_values(self, tree):
        return self._walk_list(tree, all)

    def _walk_or_values(self, tree):
        return self._walk_list(tree, any)

    def _walk_not_value(self, tree):
        expr = self.walk(tree.value)
        return lambda value: not expr(value)

    def _walk_field_comparison(self, tree):
        field = self.walk(tree.field)
        value = self.walk(tree.value)

        return lambda doc: value(field(doc))

    @classmethod
    def filter(cls, expression):
        return cls().walk(expression)

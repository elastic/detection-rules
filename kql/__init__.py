# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

import eql

from . import ast
from .eql2kql import Eql2Kql
from .errors import KqlParseError, KqlCompileError
from .evaluator import FilterGenerator
from .kql2eql import KqlToEQL
from .parser import lark_parse, KqlParser

__version__ = '0.1.4'
__all__ = (
    "ast",
    "to_eql",
    "lint",
    "parse",
    "from_eql",
    "get_evaluator",
    "KqlParseError",
    "KqlCompileError",
)


def to_eql(text, optimize=True, schema=None):
    lark_parsed = lark_parse(text)

    converted = KqlToEQL(text, schema=schema).visit(lark_parsed)
    return converted.optimize(recursive=True) if optimize else converted


def parse(text, optimize=True, schema=None):
    lark_parsed = lark_parse(text)
    converted = KqlParser(text, schema=schema).visit(lark_parsed)

    return converted.optimize(recursive=True) if optimize else converted


def lint(text):
    return parse(text, optimize=True).render()


def from_eql(tree, optimize=True):
    if not isinstance(tree, eql.ast.EqlNode):
        try:
            tree = eql.parse_query(tree, implied_any=True)
        except eql.EqlSemanticError:
            tree = eql.parse_expression(tree)

    converted = Eql2Kql().walk(tree)
    return converted.optimize(recursive=True) if optimize else converted


def get_evaluator(tree, optimize=False):
    if not isinstance(tree, ast.KqlNode):
        tree = parse(tree, optimize=optimize)

    return FilterGenerator().filter(tree)

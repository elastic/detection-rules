# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import eql

from . import ast
from .dsl import ToDsl
from .eql2kql import Eql2Kql
from .errors import KqlParseError, KqlCompileError
from .evaluator import FilterGenerator
from .kql2eql import KqlToEQL
from .parser import lark_parse, KqlParser

__version__ = '0.1.8'
__all__ = (
    "ast",
    "from_eql",
    "get_evaluator",
    "KqlParseError",
    "KqlCompileError",
    "lint",
    "parse",
    "to_dsl",
    "to_eql",
)


def to_dsl(parsed, optimize=True, schema=None):
    """Convert KQL to Elasticsearch Query DSL."""
    if not isinstance(parsed, ast.KqlNode):
        parsed = parse(parsed, optimize, schema)

    return ToDsl.convert(parsed)


def to_eql(text, optimize=True, schema=None):
    if isinstance(text, bytes):
        text = text.decode("utf-8")

    lark_parsed = lark_parse(text)

    converted = KqlToEQL(text, schema=schema).visit(lark_parsed)
    return converted.optimize(recursive=True) if optimize else converted


def parse(text, optimize: bool = True, schema: dict = None, normalize_kql_keywords: bool = False):
    if isinstance(text, bytes):
        text = text.decode("utf-8")

    lark_parsed = lark_parse(text)
    converted = KqlParser(text, schema=schema, normalize_kql_keywords=normalize_kql_keywords).visit(lark_parsed)

    return converted.optimize(recursive=True) if optimize else converted


def lint(text):
    if isinstance(text, bytes):
        text = text.decode("utf-8")

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

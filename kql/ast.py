# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import re
from string import Template

from eql.ast import BaseNode
from eql.errors import EqlCompileError
from eql.utils import is_number, is_string

__all__ = (
    "KqlNode",
    "Value",
    "Null",
    "Number",
    "Boolean",
    "List",
    "Expression",
    "String",
    "Wildcard",
    "NotValue",
    "OrValues",
    "AndValues",
    "AndExpr",
    "OrExpr",
    "NotExpr",
    "FieldComparison",
    "Field",
    "FieldRange",
    "NestedQuery",
    "Exists",
)


class KqlNode(BaseNode):
    def optimize(self, recursive=True):
        from .optimizer import Optimizer
        return Optimizer().walk(self)

    def _render(self):
        return BaseNode.render(self)

    def render(self, precedence=None, **kwargs):
        """Render an EQL node and add parentheses to support orders of operation."""
        rendered = self._render(**kwargs)
        if precedence is not None and self.precedence is not None and self.precedence > precedence:
            return '({})'.format(rendered)
        return rendered


class Value(KqlNode):
    __slots__ = "value",
    precedence = 1

    def __init__(self, value):
        self.value = value

    @classmethod
    def from_python(cls, value):
        if value is None:
            return Null()
        elif is_string(value) and ('*' in value or '?' in value):
            return Wildcard(value)
        elif isinstance(value, bool):
            return Boolean(value)
        elif is_number(value):
            return Number(value)
        elif is_string(value):
            return String(value)
        else:
            raise EqlCompileError("Unknown type {} for value {}".format(type(value).__name__, value))


class Null(Value):
    def __init__(self, value=None):
        Value.__init__(self, None)

    def _render(self):
        return "null"


class Number(Value):
    def _render(self):
        return str(self.value)


class Boolean(Value):
    def _render(self):
        return 'true' if self.value else 'false'


class String(Value):
    unescapable = re.compile(r'^[^\\():<>"*{} \t\r\n]+$')
    escapes = {"\t": "\\t", "\r": "\\r", "\"": "\\\""}

    def _render(self):
        # pass through as-is since nothing needs to be escaped
        if self.unescapable.match(self.value) is not None:
            return str(self.value)

        regex = r"[{}]".format("".join(re.escape(s) for s in sorted(self.escapes)))
        return '"{}"'.format(re.sub(regex, lambda r: self.escapes[r.group()], self.value))


class Wildcard(Value):
    escapes = {"\t": "\\t", "\r": "\\r"}
    slash_escaped = r'''^\\():<>"{} '''

    def _render(self):
        escaped = []
        for char in self.value:
            if char in self.slash_escaped:
                escaped.append("\\")
                escaped.append(char)
            elif char in self.escapes:
                escaped.append(self.escapes[char])
            else:
                escaped.append(char)
        return ''.join(escaped)


class List(KqlNode):
    __slots__ = "items",
    precedence = Value.precedence + 1
    operator = ""
    template = Template("$items")

    def __init__(self, items):
        self.items = items
        KqlNode.__init__(self)

    @property
    def delims(self):
        return {"items": " {} ".format(self.operator)}

    def __eq__(self, other):
        from .optimizer import Optimizer
        from functools import cmp_to_key
        if type(self) == type(other):
            a = list(self.items)
            b = list(other.items)
            a.sort(key=cmp_to_key(Optimizer.sort_key))
            b.sort(key=cmp_to_key(Optimizer.sort_key))
            return a == b

        return False


class NotValue(KqlNode):
    __slots__ = "value",
    template = Template("not $value")
    precedence = Value.precedence + 1

    def __init__(self, value):
        self.value = value
        KqlNode.__init__(self)


class AndValues(List):
    precedence = List.precedence + 1
    operator = "and"


class OrValues(List):
    precedence = AndValues.precedence + 1
    operator = "or"


class Field(KqlNode):
    __slots__ = "name",
    precedence = Value.precedence
    template = Template("$name")

    def __init__(self, name):
        self.name = name
        KqlNode.__init__(self)

    @property
    def path(self):
        return self.name.split(".")

    @classmethod
    def from_path(cls, path):
        dotted = ".".join(path)
        return cls(dotted)


class Expression(KqlNode):
    """Intermediate node for class hierarchy."""


class FieldRange(Expression, KqlNode):
    __slots__ = "field", "operator", "value",
    precedence = Field.precedence
    template = Template("$field $operator $value")

    def __init__(self, field, operator, value):
        self.field = field
        self.operator = operator
        self.value = value


class NestedQuery(Expression):
    __slots__ = "field", "expr",
    precedence = Field.precedence + 1
    template = Template("$field:{$expr}")

    def __init__(self, field, expr):
        self.field = field
        self.expr = expr


class FieldComparison(Expression):
    __slots__ = "field", "value",
    precedence = FieldRange.precedence
    template = Template("$field:$value")

    def __init__(self, field, value):
        self.field = field
        self.value = value


class Exists(KqlNode):
    __slots__ = tuple()
    precedence = FieldComparison.precedence
    template = Template("*")


class NotExpr(Expression):
    __slots__ = "expr",
    precedence = FieldComparison.precedence + 1
    template = Template("not $expr")

    def __init__(self, expr):
        self.expr = expr


class AndExpr(Expression, List):
    precedence = NotExpr.precedence + 1
    operator = "and"


class OrExpr(Expression, List):
    precedence = AndExpr.precedence + 1
    operator = "or"

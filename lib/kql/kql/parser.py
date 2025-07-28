# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import contextlib
import os
import re
from typing import Optional, Set

import eql
from lark import Token  # noqa: F401
from lark import Tree, Lark
from lark.exceptions import LarkError, UnexpectedEOF
from lark.visitors import Interpreter

from kql.errors import KqlParseError
from .ast import *  # noqa: F403
from .utils import check_whitespace, collect_token_positions


STRING_FIELDS = ("keyword", "text")


class KvTree(Tree):

    @property
    def child_trees(self):
        return [child for child in self.children if isinstance(child, KvTree)]

    @property
    def child_tokens(self):
        return [child for child in self.children if isinstance(child, Token)]


grammar_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kql.g")

with open(grammar_file, "rt") as f:
    grammar = f.read()

lark_parser = Lark(grammar, propagate_positions=True, tree_class=KvTree, start=['query'], parser='lalr')


def is_ipaddress(value: str) -> bool:
    """Check if a value is an ip address."""
    try:
        eql.utils.get_ipaddress(value)
        return True
    except ValueError:
        return False


def wildcard2regex(wc: str) -> re.Pattern:
    parts = wc.split("*")
    return re.compile("^{regex}$".format(regex=".*?".join(re.escape(w) for w in parts)))


def elasticsearch_type_family(mapping_type: str) -> str:
    """Get the family of type for an Elasticsearch mapping type."""
    # https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-types.html
    return {
        # range types
        "long_range": "range",
        "double_range": "range",
        "date_range": "range",
        "ip_range": "range",

        # text search types
        "annotated-text": "text",
        "completion": "text",
        "match_only_text": "text",
        "search-as_you_type": "text",

        # keyword
        "constant_keyword": "keyword",
        "wildcard": "keyword",

        # date
        "date_nanos": "date",

        # integer
        "token_count": "integer",
        "long": "integer",
        "short": "integer",
        "byte": "integer",
        "unsigned_long": "integer",

        # float
        "double": "float",
        "half_float": "float",
        "scaled_float": "float",

    }.get(mapping_type, mapping_type)


class BaseKqlParser(Interpreter):
    NON_SPACE_WS = re.compile(r"[^\S ]+")
    unquoted_escapes = {"\\t": "\t", "\\r": "\r", "\\n": "\n"}

    for special in "\\():<>\"*{}]":
        unquoted_escapes["\\" + special] = special

    unquoted_regex = re.compile("(" + "|".join(re.escape(e) for e in sorted(unquoted_escapes)) + ")")

    quoted_escapes = {"\\t": "\t", "\\r": "\r", "\\n": "\n", "\\\\": "\\", "\\\"": "\""}
    quoted_regex = re.compile("(" + "|".join(re.escape(e) for e in sorted(quoted_escapes)) + ")")

    def __init__(self, text: str, schema: dict = None, normalize_kql_keywords: bool = True) -> None:
        """Initialize the parser. Defaults to normalizing KQL keywords to lowercase."""
        self.text = text
        self.lines = [t.rstrip("\r\n") for t in self.text.splitlines(True)]
        self.scoped_field = None
        self.mapping_schema = schema
        self.star_fields = []
        self.normalize_kql_keywords = normalize_kql_keywords

        if schema:
            for field, field_type in schema.items():
                if "*" in field:
                    self.star_fields.append(wildcard2regex(field))

    def assert_lower_token(self, *tokens: Token) -> None:
        """Assert that the token is lowercase and converts token if not."""
        for token in tokens:
            lower_token = str(token).lower()
            if str(token) != lower_token:
                if self.normalize_kql_keywords:
                    token.value = lower_token
                else:
                    raise self.error(token, f"Expected '{lower_token}' but got '{token}'")

    def error(self, node, message, end=False, cls=KqlParseError, width=None, **kwargs):
        """Generate an error exception but dont raise it."""
        if kwargs:
            message = message.format(**kwargs)

        line_number = node.line - 1
        column = node.column - 1

        # get more lines for more informative error messages. three before + two after
        before = self.lines[:line_number + 1][-3:]
        after = self.lines[line_number + 1:][:3]

        source = '\n'.join(b for b in before)
        trailer = '\n'.join(a for a in after)

        # Determine if the error message can easily look like this
        #                                                     ^^^^
        if width is None and not end and node.line == node.end_line:
            if not self.NON_SPACE_WS.search(self.lines[line_number][column:node.end_column]):
                width = node.end_column - node.column

        if width is None:
            width = 1

        return cls(message, line_number, column, source, width=width, trailer=trailer)

    def __default__(self, tree):
        raise NotImplementedError("Unable to visit tree {} of type: {}".format(tree, tree.data))

    def unescape_literal(self, token):  # type: (Token) -> (int|float|str|bool)
        if token.type == "QUOTED_STRING":
            return self.convert_quoted_string(token.value)
        else:
            return self.convert_unquoted_literal(token.value)

    @contextlib.contextmanager
    def scope(self, field):
        # with self.scope(field) as field:
        #   ...
        self.scoped_field = field
        yield field
        self.scoped_field = None

    def get_field_type(self, dotted_path, lark_tree=None):
        matches_pattern = any(regex.match(dotted_path) for regex in self.star_fields)

        if self.mapping_schema is not None:
            if lark_tree is not None and dotted_path not in self.mapping_schema and not matches_pattern:
                raise self.error(lark_tree, "Unknown field")

            return self.mapping_schema.get(dotted_path)

    def get_field_types(self, wildcard_dotted_path, lark_tree=None) -> Optional[Set[str]]:
        if "*" not in wildcard_dotted_path:
            field_type = self.get_field_type(wildcard_dotted_path, lark_tree=lark_tree)
            return {field_type} if field_type is not None else None

        if self.mapping_schema is not None:
            regex = wildcard2regex(wildcard_dotted_path)
            field_types = set()

            for field, field_type in self.mapping_schema.items():
                if regex.fullmatch(field) is not None:
                    field_types.add(field_type)

            if len(field_types) == 0:
                raise self.error(lark_tree, "Unknown field")

            return field_types

    @staticmethod
    def get_literal_type(literal_value):
        if isinstance(literal_value, bool):
            return "boolean"
        elif isinstance(literal_value, float):
            return "float"
        elif isinstance(literal_value, int):
            return "long"
        elif eql.utils.is_string(literal_value):
            # this will be converted when compared to the field
            return "keyword"
        elif literal_value is None:
            return "null"
        else:
            raise NotImplementedError("Unknown literal type: {}".format(type(literal_value).__name__))

    def convert_value(self, field_name, python_value, value_tree):
        field_type = None
        field_types = self.get_field_types(field_name)
        value_type = self.get_literal_type(python_value)

        if field_types is not None:
            if len(field_types) == 1:
                field_type = list(field_types)[0]
            elif len(field_types) > 1:
                raise self.error(value_tree,
                                 f"{field_name} has multiple types {', '.join(field_types)}")

        if field_type is not None and field_type != value_type:
            field_type_family = elasticsearch_type_family(field_type)

            if field_type_family in STRING_FIELDS:
                return eql.utils.to_unicode(python_value)
            elif field_type_family in ("float", "integer"):
                try:
                    return float(python_value) if field_type_family == "float" else int(python_value)
                except ValueError:
                    pass
            elif field_type_family == "ip" and value_type == "keyword":
                if "::" in python_value or is_ipaddress(python_value) or eql.utils.is_cidr_pattern(python_value):
                    return python_value
            elif field_type_family == 'date' and value_type in STRING_FIELDS:
                # this will not validate datemath syntax
                return python_value

            raise self.error(value_tree, "Value doesn't match {field}'s type: {type}",
                             field=field_name, type=field_type)

        # otherwise, there's nothing to convert
        return python_value

    @classmethod
    def convert_unquoted_literal(cls, text):
        if text == "true":
            return True
        elif text == "false":
            return False
        elif text == "null":
            return None
        else:
            for numeric in (int, float):
                try:
                    return numeric(text)
                except ValueError:
                    pass

        text = cls.unquoted_regex.sub(lambda r: cls.unquoted_escapes[r.group()], text)
        return text

    @classmethod
    def convert_quoted_string(cls, text):
        inner_text = text[1:-1]
        unescaped = cls.quoted_regex.sub(lambda r: cls.quoted_escapes[r.group()], inner_text)
        return unescaped


class KqlParser(BaseKqlParser):
    def or_query(self, tree):
        self.assert_lower_token(*tree.child_tokens)
        terms = [self.visit(t) for t in tree.child_trees]
        return OrExpr(terms)

    def and_query(self, tree):
        self.assert_lower_token(*tree.child_tokens)
        terms = [self.visit(t) for t in tree.child_trees]
        return AndExpr(terms)

    def not_query(self, tree):
        self.assert_lower_token(*tree.child_tokens)
        return NotExpr(self.visit(tree.children[-1]))

    @contextlib.contextmanager
    def nest(self, lark_tree):
        schema = self.mapping_schema
        dotted_path = self.visit(lark_tree)

        if self.get_field_type(dotted_path, lark_tree) != "nested":
            raise self.error(lark_tree, "Expected a nested field")

        try:
            self.mapping_schema = self.mapping_schema[dotted_path]
            yield
        finally:
            self.mapping_schema = schema

    def nested_query(self, tree):
        # field_tree, query_tree = tree.child_trees
        #
        # with self.nest(field_tree) as field:
        #     return NestedQuery(field, self.visit(query_tree))

        raise self.error(tree, "Nested queries are not yet supported")

    def field_value_expression(self, tree):
        field_tree, expr = tree.child_trees

        with self.scope(self.visit(field_tree)) as field:
            # check the field against the schema
            self.get_field_types(field.name, field_tree)
            return FieldComparison(field, self.visit(expr))

    def field_range_expression(self, tree):
        field_tree, operator, literal = tree.children
        with self.scope(self.visit(field_tree)) as field:
            value = self.convert_value(field.name, self.visit(literal), literal)
            return FieldRange(field, operator, Value.from_python(value))

    def or_list_of_values(self, tree):
        self.assert_lower_token(*tree.child_tokens)
        return OrValues([self.visit(t) for t in tree.child_trees])

    def and_list_of_values(self, tree):
        self.assert_lower_token(*tree.child_tokens)
        return AndValues([self.visit(t) for t in tree.child_trees])

    def not_list_of_values(self, tree):
        self.assert_lower_token(*tree.child_tokens)
        return NotValue(self.visit(tree.children[-1]))

    def literal(self, tree):
        return self.unescape_literal(tree.children[0])

    def field(self, tree):
        literal = self.visit(tree.children[0])
        return Field(eql.utils.to_unicode(literal))

    def value(self, tree):
        if self.scoped_field is None:
            raise self.error(tree, "Value not tied to field")

        field_name = self.scoped_field.name
        token = tree.children[0]
        value = self.unescape_literal(token)

        if token.type == "UNQUOTED_LITERAL" and "*" in token.value:
            field_type = self.get_field_type(field_name)
            if len(value.replace("*", "")) == 0:
                return Exists()

            if field_type is not None and field_type not in ("keyword", "wildcard"):
                raise self.error(tree, "Unable to perform wildcard on field {field} of {type}",
                                 field=field_name, type=field_type)

            return Wildcard(token.value)

        # try to convert the value to the appropriate type
        # example: 1 -> "1" if the field is actually keyword
        value = self.convert_value(field_name, value, tree)
        return Value.from_python(value)


def lark_parse(text):
    if not text.strip():
        raise KqlParseError("No query provided", 0, 0, "")

    walker = BaseKqlParser(text)

    try:
        tree = lark_parser.parse(text)

        # Check for whitespace around "and" and "or" tokens
        lines = text.split('\n')
        check_whitespace(collect_token_positions(tree, ["and", "or"]), lines)

        return tree
    except UnexpectedEOF:
        raise KqlParseError("Unexpected EOF", len(walker.lines), len(walker.lines[-1].strip()), walker.lines[-1])
    except LarkError as exc:
        raise KqlParseError("Invalid syntax", exc.line - 1, exc.column - 1,
                            '\n'.join(walker.lines[exc.line - 2:exc.line]))

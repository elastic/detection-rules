# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import eql

from .parser import BaseKqlParser

NOT_SUPPORTED_EQL_FIELDS = ["text"]
#  https://github.com/elastic/eql/issues/17

class KqlToEQL(BaseKqlParser):

    #
    # Lark Visit methods
    #
    @staticmethod
    def to_eql_field(name):
        path = name.split(".")
        return eql.ast.Field(path[0], path[1:])

    def or_query(self, tree):
        terms = [self.visit(t) for t in tree.child_trees]
        return eql.ast.Or(terms)

    def and_query(self, tree):
        terms = [self.visit(t) for t in tree.child_trees]
        return eql.ast.And(terms)

    def not_query(self, tree):
        return eql.ast.Not(self.visit(tree.children[-1]))

    def nested_query(self, tree):
        raise self.error(tree, "Unable to convert nested query to EQL")

    def field_range_expression(self, tree):
        field_tree, operator, literal_tree = tree.children
        field_name = self.visit(field_tree)

        # check the field against the schema
        self.get_field_type(field_name, field_tree)

        # get and convert the value
        value = self.convert_value(field_name, self.visit(literal_tree), literal_tree)
        literal = eql.ast.Literal.from_python(value)

        field = self.to_eql_field(field_name)
        return eql.ast.Comparison(field, operator.value, literal)

    def field_value_expression(self, tree):
        field_tree, value_tree = tree.child_trees

        with self.scope(self.visit(field_tree)) as field_name:
            # check the field against the schema

            type_mapping = self.get_field_type(field_name, field_tree)
            if type_mapping in NOT_SUPPORTED_EQL_FIELDS:
                err_msg = f"{field_name} uses an unsupported elasticsearch eql field_type {type_mapping}"
                raise eql.EqlSemanticError(err_msg, field_tree.line, field_tree.column, self.text)

            return self.visit(value_tree)

    def or_list_of_values(self, tree):
        children = [self.visit(t) for t in tree.child_trees]
        return eql.ast.Or(children)

    def and_list_of_values(self, tree):
        children = [self.visit(t) for t in tree.child_trees]
        return eql.ast.And(children)

    def not_list_of_values(self, tree):
        return eql.ast.Not(self.visit(tree.children[-1]))

    def field(self, tree):
        literal = self.visit(tree.children[0])
        return eql.utils.to_unicode(literal)

    def value(self, tree):
        # TODO: check the logic for kuery.peg
        value = self.unescape_literal(tree.children[0])

        if self.scoped_field is None:
            raise self.error(tree, "Value not tied to field")

        field_name = self.scoped_field
        field = self.to_eql_field(field_name)
        value = self.convert_value(field_name, value, tree)
        value_ast = eql.ast.Literal.from_python(value)

        if value is None:
            return eql.ast.IsNull(field)

        if eql.utils.is_string(value) and value.replace("*", "") == "":
            return eql.ast.IsNotNull(field)

        if eql.utils.is_string(value) and "*" in value:
            return eql.ast.FunctionCall("wildcard", [field, value_ast])

        if self.get_field_types(field_name) == {"ip"} and "/" in value:
            return eql.ast.FunctionCall("cidrMatch", [field, value_ast])

        return eql.ast.Comparison(field, "==", value_ast)

    def literal(self, tree):
        return self.unescape_literal(tree.children[0])

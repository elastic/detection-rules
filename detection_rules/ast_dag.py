# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""AST drawing."""

import os
import sys
import random
import hashlib
from collections import namedtuple
from contextlib import contextmanager, nullcontext

import graphviz
import eql

Context = namedtuple("Context", ["graph", "colors"])
colors = ("red", "blue", "green", "orange", "darkorchid", "pink", "brown", "cyan", "purple")
random = random.Random()


class Digraph(graphviz.Digraph):
    def _repr_mimebundle_(self, *args, **kwargs):
        bundle = super(graphviz.Digraph, self)._repr_mimebundle_(*args, **kwargs)
        bundle["text/plain"] = None
        return bundle


def next_color(stack):
    for c in colors:
        if c not in stack:
            return c
    return stack[0]


@contextmanager
def new_color(ctx, attr):
    new_color = next_color(ctx.colors)
    ctx.colors.append(new_color)
    ctx.graph.attr(attr, color=new_color, style="solid")
    try:
        yield
    finally:
        ctx.graph.attr(attr, color="black", style="dashed")


def get_node_id(label):
    label = f"{label}-{random.random()}"
    return hashlib.md5(label.encode("utf-8")).hexdigest()


def visit_ast(node, ctx, negate=False):
    node_id = get_node_id(node.render())

    if isinstance(node, eql.ast.Literal):
        ctx.graph.node(node_id, node.render())
    elif type(node) is eql.ast.Field:
        ctx.graph.node(node_id, node.render())
    elif type(node) is eql.ast.Or:
        ctx.graph.node(node_id, "or")
        for term in node.terms:
            ctx.graph.attr("edge", color="black", style="solid")
            with nullcontext() if negate else new_color(ctx, "edge"):
                term_id = visit_ast(term, ctx, negate)
                ctx.graph.edge(node_id, term_id)
    elif type(node) is eql.ast.And:
        ctx.graph.node(node_id, "and")
        for term in node.terms:
            ctx.graph.attr("edge", color="black", style="solid")
            with new_color(ctx, "edge") if negate else nullcontext():
                term_id = visit_ast(term, ctx, negate)
                ctx.graph.edge(node_id, term_id)
    elif type(node) is eql.ast.Not:
        ctx.graph.node(node_id, "not")
        term_id = visit_ast(node.term, ctx, not negate)
        ctx.graph.edge(node_id, term_id)
    elif type(node) is eql.ast.IsNull:
        null_id = get_node_id("null")
        ctx.graph.node(node_id, "==")
        expr_id = visit_ast(node.expr, ctx, negate)
        ctx.graph.node(null_id, "null")
        ctx.graph.edge(node_id, expr_id)
        ctx.graph.edge(node_id, null_id)
    elif type(node) is eql.ast.IsNotNull:
        null_id = get_node_id("null")
        ctx.graph.node(node_id, "!=")
        expr_id = visit_ast(node.expr, ctx, negate)
        ctx.graph.node(null_id, "null")
        ctx.graph.edge(node_id, expr_id)
        ctx.graph.edge(node_id, null_id)
    elif type(node) is eql.ast.InSet:
        ctx.graph.node(node_id, "in")
        ctx.graph.attr("edge", color="black", style="solid")
        expr_id = visit_ast(node.expression, ctx, negate)
        ctx.graph.edge(node_id, expr_id)
        for term in node.container:
            with nullcontext() if negate else new_color(ctx, "edge"):
                term_id = visit_ast(term, ctx, negate)
                ctx.graph.edge(node_id, term_id)
    elif type(node) is eql.ast.Comparison:
        ctx.graph.node(node_id, node.comparator)
        left_id = visit_ast(node.left, ctx, negate)
        right_id = visit_ast(node.right, ctx, negate)
        ctx.graph.edge(node_id, left_id)
        ctx.graph.edge(node_id, right_id)
    elif type(node) is eql.ast.EventQuery:
        visit_ast(node.query, ctx, negate)
    elif type(node) is eql.ast.PipedQuery:
        visit_ast(node.first, ctx, negate)
    elif type(node) is eql.ast.FunctionCall:
        ctx.graph.node(node_id, node.name.lower())
        ctx.graph.attr("edge", color="black", style="solid")
        arg_id = visit_ast(node.arguments[0], ctx, negate)
        ctx.graph.edge(node_id, arg_id)
        for arg in node.arguments[1:]:
            with nullcontext() if negate else new_color(ctx, "edge"):
                arg_id = visit_ast(arg, ctx, negate)
                ctx.graph.edge(node_id, arg_id)
    else:
        raise ValueError(f"Unable to draw node type: {type(node)}")

    return node_id


def draw_ast(ast, graph=None):
    random.seed(ast.render())
    if not graph:
        graph = Digraph(format="svg")
    visit_ast(ast, Context(graph, ["black"]))
    return graph


def draw_query(query, filename):
    ast = eql.parse_query(query)
    name, ext = os.path.splitext(filename)
    graph = graphviz.Digraph(comment=query, filename=name, format=ext[1:])
    draw_ast(ast, graph)
    graph.render(name)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.stderr.write(f"usage: {sys.argv[0]} <query> <filename>\n")
        sys.exit(1)
    draw_query(sys.argv[1], sys.argv[2])

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.
from antlr4 import ParserRuleContext
from antlr4.tree.Trees import Trees
from esql.errors import ESQLSemanticError
from esql.EsqlBaseParser import EsqlBaseParser


def print_tree(parser: EsqlBaseParser, ctx: ParserRuleContext):
    """Print the parse tree."""
    print(Trees.toStringTree(ctx, None, parser))


def pretty_print_tree(ctx: EsqlBaseParser.SingleStatementContext, indent: int = 0, is_last: bool = True):
    """Pretty print the parse tree."""
    if ctx is None:
        return

    # Indentation and prefix logic
    indent_str = '    ' * indent
    prefix = '└── ' if is_last else '├── '

    # Print the current context
    node_label = type(ctx).__name__ + ': ' + ctx.getText()
    print(f"{indent_str}{prefix}{node_label}")

    # Recursively pretty print each child
    children = [ctx.getChild(i) for i in range(ctx.getChildCount())]
    for i, child in enumerate(children):
        pretty_print_tree(child, indent + 1, i == len(children) - 1)


def get_node(tree: EsqlBaseParser.SingleStatementContext, ctx: ParserRuleContext):
    """Return the first node of type ctx in the tree."""
    # fail if ctx is not a valid context
    if not issubclass(ctx, ParserRuleContext):
        raise ESQLSemanticError(f"Invalid context: {ctx}")

    nodes = []
    for child in tree.children:
        if isinstance(child, ctx):
            nodes.append(child)
        elif hasattr(child, "children"):
            nodes.extend(get_node(child, ctx))

    return nodes

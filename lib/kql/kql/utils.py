# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import re

from lark import (
    Token,
    Tree,
)

from kql.errors import KqlParseError


def check_whitespace(token_positions: list[tuple[int, int, str]], lines: list[str]) -> None:
    """Check for whitespace around a token."""
    for line_num, column, token in token_positions:
        # Check the substring at the given position
        line = lines[line_num - 1]
        start = column - 1
        end = column + len(token) - 1

        # Handle cases where token starts at the beginning of the line and is followed by whitespace
        if start == 0 and (end < len(line) and re.match(r"\s", line[end])):
            continue

        # Check for whitespace around the token
        if (
            start > 0
            and ((end < len(line) and re.match(r"\s", line[end])) or end == len(line))
            and re.match(r"\s", line[start - 1])
        ):
            continue
        raise KqlParseError(
            error_msg=f"Missing whitespace around '{token}' token",
            line=line_num,
            column=column,
            source=line,
            width=len(token),
            trailer=None
        )


def collect_token_positions(tree: Tree, token_list: list[str]) -> list[tuple[int, int, str]]:
    """Collect token positions from a tree for a list of tokens."""
    token_positions = []
    for child in tree.children:
        if isinstance(child, Token) and child.value.lower() in [token.lower() for token in token_list]:
            token_positions.append((child.line, child.column, child.value))
        elif isinstance(child, Tree):
            token_positions.extend(collect_token_positions(child, token_list))
    return token_positions

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import re

from lark import Token  # noqa: F401
from lark import Tree

from typing import List


def check_whitespace(token_positions: List, token: str, lines: List[str]) -> None:
    """Check for whitespace around a token."""
    for line_num, column in token_positions:
        # Check the substring at the given position
        line = lines[line_num - 1]
        start = column - 1
        end = column + len(token) - 1
        if (
            start > 0
            and (end < len(line) and re.match(r"\s", line[end]) or end == len(line))
            and re.match(r"\s", line[start - 1])
        ):
            continue
        else:
            raise ValueError(f"Missing whitespace around '{token}' token", line)


def collect_token_positions(tree: Tree, token: str) -> List:
    """Collect token positions from a tree."""
    token_positions = []
    for child in tree.children:
        if isinstance(child, Token) and child.value.lower() in [token]:
            token_positions.append((child.line, child.column))
        elif isinstance(child, Tree):
            token_positions.extend(collect_token_positions(child, token))
    return token_positions

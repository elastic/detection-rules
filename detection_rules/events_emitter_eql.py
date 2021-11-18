# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Functions for generating event documents that would trigger a given rule."""

from typing import List
from eql import ast

def emit_events_eql(expr: ast.Expression) -> List[str]:
    docs = [{}]
    return docs

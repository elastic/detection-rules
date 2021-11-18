# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Functions for generating event documents that would trigger a given rule."""

import sys
from typing import List
import eql

def emit_events(node: eql.ast.BaseNode) -> List[str]:
    try:
        return emitters[type(node)](node)
    except KeyError:
        sys.stderr.write(f"##############################\n")
        sys.stderr.write(f"{node}\n")
        sys.stderr.write(f"{type(node)}\n")
        sys.stderr.write(f"{dir(node)}\n")
        sys.exit(1)

def emit_Comparison(node: eql.ast.Comparison):
    ops = {
        str: {
            "==": lambda s: s,    "!=": lambda s: "!" + s,
        },
        int: {
            "==": lambda n: n,    "!=": lambda n: n + 1,
            ">=": lambda n: n,    "<=": lambda n: n,
             ">": lambda n: n + 1, "<": lambda n: n - 1,
        },
        bool: {
            "==": lambda b: b,    "!=": lambda b: not b,
        }
    }

    value = ops[type(node.right.value)][node.comparator](node.right.value)
    for part in reversed(node.left.render().split(".")):
        doc = { part: value }
        value = doc
    return [doc]

def emit_EventQuery(node: eql.ast.EventQuery):
    docs = emit_events(node.query)
    if node.event_type != "any":
        for doc in docs:
            doc.update({"event": { "category": node.event_type }})
    return docs

def emit_PipedQuery(node: eql.ast.PipedQuery):
    if node.pipes:
        raise NotImplemented("Pipes are unsupported")
    return emit_events(node.first)

emitters = {
    eql.ast.Comparison: emit_Comparison,
    eql.ast.EventQuery: emit_EventQuery,
    eql.ast.PipedQuery: emit_PipedQuery,
}

def _emit_events_query(query: str) -> List[str]:
    """
    >>> _emit_events_query('process where process.name == "regsvr32.exe"')
    '[{"event": {"category": "process"}, "process": {"name": "regsvr32.exe"}}]'
    >>> _emit_events_query('process where process.name != "regsvr32.exe"')
    '[{"event": {"category": "process"}, "process": {"name": "!regsvr32.exe"}}]'
    >>> _emit_events_query('process where process.pid == 0')
    '[{"event": {"category": "process"}, "process": {"pid": 0}}]'
    >>> _emit_events_query('process where process.pid != 0')
    '[{"event": {"category": "process"}, "process": {"pid": 1}}]'
    >>> _emit_events_query('process where process.pid >= 0')
    '[{"event": {"category": "process"}, "process": {"pid": 0}}]'
    >>> _emit_events_query('process where process.pid <= 0')
    '[{"event": {"category": "process"}, "process": {"pid": 0}}]'
    >>> _emit_events_query('process where process.pid > 0')
    '[{"event": {"category": "process"}, "process": {"pid": 1}}]'
    >>> _emit_events_query('process where process.pid < 0')
    '[{"event": {"category": "process"}, "process": {"pid": -1}}]'
    >>> _emit_events_query('process where process.code_signature.exists == true')
    '[{"event": {"category": "process"}, "process": {"code_signature": {"exists": true}}}]'
    >>> _emit_events_query('process where process.code_signature.exists != true')
    '[{"event": {"category": "process"}, "process": {"code_signature": {"exists": false}}}]'
    >>> _emit_events_query('any where network.protocol == "some protocol"')
    '[{"network": {"protocol": "some protocol"}}]'

    """
    import json

    with eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
        return json.dumps(emit_events(eql.parse_query(query)), sort_keys=True)

if __name__ == "__main__":
    import doctest
    doctest.testmod()

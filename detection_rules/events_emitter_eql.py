# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Functions for generating event documents that would trigger a given rule."""

import sys
import string
import random
from typing import List
import eql

__all__ = (
    "emit_events",
    "get_ast_stats",
)

class emitter:
    emitters = {}

    def __init__(self, node_type):
        self.node_type = node_type
        self.successful = 0
        self.total = 0

    def __call__(self, func):
        if self.node_type in self.emitters:
            raise ValueError(f"Duplicate emitter for {self.node_type}: {func.__name__}")
        self.emitters[self.node_type] = self

        def wrapper(*args, **kwargs):
            self.total += 1
            ret = func(*args, **kwargs)
            self.successful += 1
            return ret

        self.wrapper = wrapper
        return wrapper

    @classmethod
    def emit_events(cls, node: eql.ast.BaseNode):
        return cls.emitters[type(node)].wrapper(node)

    @classmethod
    def get_stats(cls):
        return {k.__name__: (v.successful, v.total) for k,v in cls.emitters.items()}

def emit_events(node: eql.ast.BaseNode) -> List[str]:
    return emitter.emit_events(node)

def get_ast_stats():
    return emitter.get_stats()

# https://stackoverflow.com/questions/7204805/how-to-merge-dictionaries-of-dictionaries/7205107#7205107
def merge_dicts(a, b, path=None):
    "merges b into a"
    if path is None:
        path = []
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                merge_dicts(a[key], b[key], path + [str(key)])
            else:
                a[key] = b[key]
        else:
            a[key] = b[key]
    return a

def get_random_string(min_length, condition=None, allowed_chars=string.ascii_letters):
    l = [random.choice(allowed_chars) for _ in range(min_length)]
    while condition and not condition("".join(l)):
        l.insert(random.randint(0, len(l)-1), random.choice(allowed_chars))
    return "".join(l)

@emitter(eql.ast.Field)
def emit_Field(node: eql.ast.Field, value):
    for part in reversed([node.base] + node.path):
        value = { part: value }
    return value

@emitter(eql.ast.Or)
def emit_Or(node: eql.ast.Or):
    doc = {}
    if type(node.terms) != list:
        raise NotImplementedError(f"Unsupported terms type: {type(node.terms)}")
    for term in node.terms:
        term_docs = emit_events(term)
        if len(term_docs) > 1:
            raise NotImplementedError("Unsupported multi-event term")
        doc.update(term_docs[0])
    return [doc]

@emitter(eql.ast.And)
def emit_And(node: eql.ast.And):
    doc = {}
    if type(node.terms) != list:
        raise NotImplementedError(f"Unsupported terms type: {type(node.terms)}")
    for term in node.terms:
        term_docs = emit_events(term)
        if len(term_docs) > 1:
            raise NotImplementedError("Unsupported multi-event term")
        merge_dicts(doc, term_docs[0])
    return [doc]

@emitter(eql.ast.Not)
def emit_Not(node: eql.ast.Not):
    if isinstance(node.term, eql.ast.InSet):
        return emit_InSet(node.term, negate=True)

    if isinstance(node.term, eql.ast.FunctionCall) and node.term.name == 'wildcard':
        if len(node.term.arguments) == 2 and isinstance(node.term.arguments[1], eql.ast.String):
            lhs, rhs = node.term.arguments
            return emit_Comparison(eql.ast.Comparison(lhs, eql.ast.Comparison.NE, rhs))

    raise NotImplementedError(f"Unsupported term negation: {type(node.term)}")

@emitter(eql.ast.InSet)
def emit_InSet(node: eql.ast.InSet, negate=False):
    if type(node.expression) != eql.ast.Field:
        raise NotImplementedError(f"Unsupported expression type: {type(node.expression)}")
    if type(node.container) != list:
        raise NotImplementedError(f"Unsupported container type: {type(node.container)}")
    if negate:
        min_length = 3 * len(node.container)
        values = set(x.value for x in node.container)
        value = get_random_string(min_length, lambda x: x not in values)
    else:
        value = node.container[0].value
    doc = emit_Field(node.expression, value)
    return [doc]

@emitter(eql.ast.Comparison)
def emit_Comparison(node: eql.ast.Comparison):
    ops = {
        eql.ast.String: {
            "==": lambda s: s,    "!=": lambda s: "!" + s,
        },
        eql.ast.Number: {
            "==": lambda n: n,    "!=": lambda n: n + 1,
            ">=": lambda n: n,    "<=": lambda n: n,
             ">": lambda n: n + 1, "<": lambda n: n - 1,
        },
        eql.ast.Boolean: {
            "==": lambda b: b,    "!=": lambda b: not b,
        }
    }

    if type(node.left) != eql.ast.Field:
        raise NotImplementedError(f"Unsupported LHS type: {type(node.left)}")
    if type(node.right) not in (eql.ast.String, eql.ast.Number, eql.ast.Boolean):
        raise NotImplementedError(f"Unsupported RHS type: {type(node.left)}")

    value = ops[type(node.right)][node.comparator](node.right.value)
    doc = emit_Field(node.left, value)
    return [doc]

@emitter(eql.ast.EventQuery)
def emit_EventQuery(node: eql.ast.EventQuery):
    if type(node.event_type) != str:
        raise NotImplementedError(f"Unsupported event_type type: {type(node.event_type)}")
    docs = emit_events(node.query)
    if node.event_type != "any":
        for doc in docs:
            doc.update({"event": { "category": node.event_type }})
    return docs

@emitter(eql.ast.PipedQuery)
def emit_PipedQuery(node: eql.ast.PipedQuery):
    if node.pipes:
        raise NotImplementedError("Pipes are unsupported")
    return emit_events(node.first)

@emitter(eql.ast.FunctionCall)
def emit_FunctionCall(node: eql.ast.FunctionCall):
    if node.name != "wildcard":
        raise NotImplementedError(f"Unsupported function: {node.name}")
    if len(node.arguments) != 2:
        raise NotImplementedError(f"Unsupported number of arguments: {len(node.arguments)}")
    if type(node.arguments[0]) != eql.ast.Field:
        raise NotImplementedError(f"Unsupported argument type: {type(node.argument[0])}")
    if type(node.arguments[1]) != eql.ast.String:
        raise NotImplementedError(f"Unsupported argument type: {type(node.argument[1])}")
    value = node.arguments[1].value
    value = value.replace("?", "_")
    value = value.replace("*", "")
    doc = emit_Field(node.arguments[0], value.lower())
    return [doc]

@emitter(eql.ast.BaseNode)
@emitter(eql.ast.Expression)
@emitter(eql.ast.EqlNode)
@emitter(eql.ast.Literal)
@emitter(eql.ast.String)
@emitter(eql.ast.Number)
@emitter(eql.ast.Null)
@emitter(eql.ast.Boolean)
@emitter(eql.ast.TimeRange)
@emitter(eql.ast.TimeUnit)
@emitter(eql.ast.IsNotNull)
@emitter(eql.ast.IsNull)
@emitter(eql.ast.MathOperation)
@emitter(eql.ast.NamedSubquery)
@emitter(eql.ast.NamedParams)
@emitter(eql.ast.SubqueryBy)
@emitter(eql.ast.Join)
@emitter(eql.ast.Sequence)
@emitter(eql.ast.PipeCommand)
@emitter(eql.ast.EqlAnalytic)
@emitter(eql.ast.Definition)
@emitter(eql.ast.BaseMacro)
@emitter(eql.ast.CustomMacro)
@emitter(eql.ast.Macro)
@emitter(eql.ast.Constant)
@emitter(eql.ast.PreProcessor)
def emit_not_implemented(node: eql.ast.BaseNode):
    sys.stderr.write(f"##### Emitter for {type(node)} is not implemented #####\n")
    sys.stderr.write(f"\n{node}\n")
    sys.stderr.write(f"\n{dir(node)}\n")
    raise NotImplementedError(f"Emitter not implemented: {type(node)}")

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

    >>> _emit_events_query('process where process.name == "regsvr32.exe" and process.parent.name == "cmd.exe"')
    '[{"event": {"category": "process"}, "process": {"name": "regsvr32.exe", "parent": {"name": "cmd.exe"}}}]'

    >>> _emit_events_query('process where process.name == "regsvr32.exe" or process.parent.name == "cmd.exe"')
    '[{"event": {"category": "process"}, "process": {"parent": {"name": "cmd.exe"}}}]'

    >>> _emit_events_query('process where process.name == "regsvr32.exe" or process.name == "cmd.exe"')
    '[{"event": {"category": "process"}, "process": {"name": "regsvr32.exe"}}]'

    >>> _emit_events_query('process where process.name in ("regsvr32.exe", "cmd.exe")')
    '[{"event": {"category": "process"}, "process": {"name": "regsvr32.exe"}}]'

    >>> _emit_events_query('process where process.name : "REG?*32.EXE"')
    '[{"event": {"category": "process"}, "process": {"name": "reg_32.exe"}}]'
    """
    import json

    with eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
        return json.dumps(emit_events(eql.parse_query(query)), sort_keys=True)

if __name__ == "__main__":
    import doctest
    doctest.testmod()

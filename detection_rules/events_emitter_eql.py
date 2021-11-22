# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Functions for generating event documents that would trigger a given rule."""

import sys
import string
import random
import json
import copy
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

def deep_merge(a, b, path=None):
    """Recursively merge two docs

    >>> _deep_merge = lambda *args: json.dumps(deep_merge(*args), sort_keys=True)
    >>> _deep_merge({}, {"a": "A"})
    '{"a": "A"}'
    >>> _deep_merge({"a": "A"}, {})
    '{"a": "A"}'
    >>> _deep_merge({"a": "A"}, {"b": "B"})
    '{"a": "A", "b": "B"}'
    >>> _deep_merge({"a": "A"}, {"a": "B"})
    Traceback (most recent call last):
      ...
    ValueError: Destination field already exists: a ("A" != "B")
    >>> _deep_merge({"a": ["A"]}, {"a": ["A"]})
    '{"a": ["A"]}'
    >>> _deep_merge({"a": ["A"]}, {"a": ["B"]})
    '{"a": ["A", "B"]}'
    >>> _deep_merge({"a": ["A"]}, {"a": [{"b": "B"}]})
    '{"a": ["A", {"b": "B"}]}'
    >>> _deep_merge({"a": {"b": {"c": "C"}}}, {"a": {"b": {"c": "D"}}})
    Traceback (most recent call last):
      ...
    ValueError: Destination field already exists: a.b.c ("C" != "D")
    """
    for key in b:
        if key in a:
            path = (path or []) + [str(key)]
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                deep_merge(a[key], b[key], path)
            elif isinstance(a[key], list) and isinstance(b[key], list):
                a[key].extend(x for x in b[key] if x not in a[key])
            elif a[key] != b[key]:
                raise ValueError(f"Destination field already exists: {'.'.join(path)} (\"{a[key]}\" != \"{b[key]}\")")
        else:
            a[key] = b[key]
    return a

def get_random_string(min_length, condition=None, allowed_chars=string.ascii_letters):
    l = random.choices(allowed_chars, k=min_length)
    while condition and not condition("".join(l)):
        l.insert(random.randrange(len(l)), random.choice(allowed_chars))
    return "".join(l)

def get_random_octets(n):
    return [random.randint(1, 254) for _ in range(n-1)]

def fuzzy_ip(nr_octets, sep, fmt, condition = None, fuzziness = 0):
    if fuzziness:
        octets = get_random_octets(nr_octets)
    else:
        octets = [1] * nr_octets
    def to_str(o):
        return sep.join(fmt.format(x) for x in o)
    while condition and not condition(to_str(octets)):
        octets = get_random_octets(nr_octets)
    return to_str(octets)

def fuzzy_ipv4(*args, **kwargs):
    return fuzzy_ip(4, ".", "{:d}")

def fuzzy_ipv6(*args, **kwargs):
    return fuzzy_ip(6, ":", "{:x}")

def fuzzy_choice(options, fuzziness = 0):
    if fuzziness:
        return random.choice(options)
    else:
        return options[0]

def fuzzy_iter(iterable):
    # shortcut: should shuffle randomly
    return iterable

@emitter(eql.ast.Field)
def emit_Field(node: eql.ast.Field, value):
    # shortcut: this kind of info should come from ECS
    list_fields = (
        "event.type",
        "process.args",
        "process.parent.args",
    )
    if node.render() in list_fields:
        value = [value]
    for part in reversed([node.base] + node.path):
        value = { part: value }
    return value

@emitter(eql.ast.Or)
def emit_Or(node: eql.ast.Or):
    docs = []
    for term in fuzzy_iter(node.terms):
        docs.extend(emit_events(term))
    return docs

@emitter(eql.ast.And)
def emit_And(node: eql.ast.And):
    docs = []
    for term in node.terms:
        term_docs = emit_events(term)
        if not docs:
            docs = term_docs
            continue
        new_docs = []
        for term_doc in term_docs:
            for doc in docs:
                new_docs.append(deep_merge(copy.deepcopy(term_doc), doc))
        docs = new_docs
    return docs

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
    docs = []
    if negate:
        min_length = 3 * len(node.container)
        values = set(x.value for x in node.container)
        value = get_random_string(min_length, lambda x: x not in values)
        docs.append(emit_Field(node.expression, value))
    else:
        for term in fuzzy_iter(node.container):
            docs.append(emit_Field(node.expression, term.value))
    return docs

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
            deep_merge(doc, {"event": { "category": node.event_type }})
    return docs

@emitter(eql.ast.PipedQuery)
def emit_PipedQuery(node: eql.ast.PipedQuery):
    if node.pipes:
        raise NotImplementedError("Pipes are unsupported")
    return emit_events(node.first)

@emitter(eql.ast.SubqueryBy)
def emit_SubqueryBy(node: eql.ast.SubqueryBy, join_values: List[str]):
    if any(not isinstance(value, eql.ast.Field) for value in node.join_values):
        raise NotImplementedError(f"Unsupported join values: {node.join_values}")
    if node.fork:
        raise NotImplementedError(f"Unsupported fork: {node.fork}")
    docs = emit_events(node.query)
    for i, field in enumerate(node.join_values):
        if i == len(join_values):
            join_values.append(get_random_string(3 * len(node.join_values)))
        for doc in docs:
            deep_merge(doc, emit_Field(field, join_values[i]))
    return docs

@emitter(eql.ast.Sequence)
def emit_Sequence(node: eql.ast.Sequence):
    docs = []
    if any(not isinstance(query, eql.ast.SubqueryBy) for query in node.queries):
        raise NotImplementedError(f"Unsupported sub-queries: {node.queries}")
    join_values = []
    for query in node.queries:
        docs.extend(emit_SubqueryBy(query, join_values=join_values))
    if node.close:
        docs.extend(emit_events(node.close))
    return docs

@emitter(eql.ast.FunctionCall)
def emit_FunctionCall(node: eql.ast.FunctionCall):
    if node.name != "wildcard":
        raise NotImplementedError(f"Unsupported function: {node.name}")
    if type(node.arguments[0]) != eql.ast.Field:
        raise NotImplementedError(f"Unsupported argument type: {type(node.argument[0])}")
    if type(node.arguments[1]) != eql.ast.String:
        raise NotImplementedError(f"Unsupported argument type: {type(node.argument[1])}")
    value = fuzzy_choice(node.arguments[1:]).value
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
@emitter(eql.ast.Join)
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
    sys.stderr.write(f"\nSlots:\n")
    for slot,value in node.iter_slots():
        sys.stderr.write(f"  {slot}: {value}\n")

    raise NotImplementedError(f"Emitter not implemented: {type(node)}")

def _emit_events_query(query: str) -> List[str]:
    """
    >>> _emit_events_query('any where network.protocol == "some protocol" and network.protocol == "some other protocol"')
    Traceback (most recent call last):
      ...
    ValueError: Destination field already exists: network.protocol ("some other protocol" != "some protocol")

    """
    with eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
        return json.dumps(emit_events(eql.parse_query(query)), sort_keys=True)

if __name__ == "__main__":
    import doctest
    random.seed(0xcafecafe)
    doctest.testmod()

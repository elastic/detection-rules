## Signals generation

The aim is to synthetize one or more documents that would make a given detection rule trigger a SIEM signal.


For instance, given the EQL query

```
network where destination.port == 22
```

the _minimal matching document_ (with `@timestamp` omitted for readability) is

```
{"event": {"category": ["network"]}, "destination": {"port": 22}}
```

Independently from any other field being present, those in the minimal matching document are required by the detection engine for generating a signal.

Depending on the rule, multiple documents might be needed. Indeed

```
sequence by user.id
    [process where process.name : "cmd.exe"]
    [process where process.parent.name : "cmd.exe"]
```
requires two documents as below

```
{"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}, "user": {"id": "xgG"}},
{"event": {"category": ["process"]}, "process": {"parent": {"name": "cmd.exe"}}, "user": {"id": "xgG"}},
```
The fields content is generated pseudo-randomly according to each field type and the constraints specified in the query itself.

## Approach

The idea is to use the query itself to build the _minimal matching document_.

These are the high level steps:

1. The query is parsed and translated into the corresponding abstract syntax tree (AST)
2. The AST is visited and the fields constraints are collected
3. The constraints of each field are solved, if possible, and stored in a set of _field-value_ pairs
4. The set of _field-value_ pairs is translated to a document

Details about the single steps follow.

### Generating the AST

AST generation levereges on the [EQL parser API](https://eql.readthedocs.io/en/latest/api/parser.html) as used by the rule validator. Therefore only EQL and Kuery rules (which AST can be translated to EQL) are currently supported.

The relevant code (from [detection_rules/events_emitter.py](../detection_rules/events_emitter.py)) is:

```python
def ast_from_rule(cls, rule):
    if rule.type not in ("query", "eql"):
        raise NotImplementedError(f"Unsupported rule type: {rule.type}")
    elif rule.language == "eql":
        return rule.validator.ast
    elif rule.language == "kuery":
        return rule.validator.to_eql() # shortcut?
    else:
        raise NotImplementedError(f"Unsupported query language: {rule.language}")
```

### Collecting the constraints

Constraints collection is done in a recursive fashion, every [AST node](https://eql.readthedocs.io/en/latest/api/ast.html) is matched by an _emitter_ which purpose is to extract the constraints from the node.

For instance (from [detection_rules/events_emitter_eql.py](../detection_rules/events_emitter_eql.py))

```python
@emitter(eql.ast.Field)
def emit_Field(node: eql.ast.Field, value: str, negate: bool) -> Constraints:
    constraint_name = "!=" if negate else "=="
    return Constraints(node.render(), constraint_name, value)
```

Constraints are essentially a list of tuples associated to each field. In the case of the sequence query above, a simplified representation of its constraints is

```json
[
    {
        "process.name": [
            ["wildcard", "cmd.exe"]
        ]
    },
    {
        "process.parent.name": [
            ["wildcard", "cmd.exe"]
        ]
    }
]
```

Note how it's a list of two dictionaries, one for each document to be generated, and how each can arbitrarily grow in the fields it can contain and the constraints each field can have.

Also, the `user.id` join value is omitted for readability. As a matter of fact, when the first document in the sequence is generated, all its join values are propagated (and named) as additional constraints on the following documents of that sequence instance.

### Solving the constraints

Constraints are arbitrary, solution spaces are huge and space/time is a finite resource. [Constraint programming](https://en.wikipedia.org/wiki/Constraint_programming) is a branch on its own and comes with its Python [module](https://pypi.org/project/python-constraint/). Nevertheless we develop our solution in [detection_rules/constraints.py](../detection_rules/constraints.py).

Each document to be generated is represented by a `Constraints` object which collects all the fields that need to be present (or absent). Each field is associated with the list of constraints it needs to satisfy, if possible. The appropriate constraint solver is determined by the field type as identified by the ECS or some other custom schema.

The constraints solvers perform the following steps:

1. validate all the constraints and their arguments
2. check that constraints are not conflicting or resulting in the empty solution space
3. check that any specified value satisfies all the constraints
4. if no value was specified, generate one that meets all the constraints

As example, the most simple solver

```python
@solver("boolean", "==", "!=")
def solve_boolean_constraints(cls, field, value, constraints):
    for k,v in constraints:
        if k == "==":
            v = bool(v)
            if value is None or value == v:
                value = v
            else:
                raise ConflictError(f"is already {value}, cannot set to {v}", field, k)
        elif k == "!=":
            v = bool(v)
            if value is None or value != v:
                value = not v
            else:
                raise ConflictError(f"is already {value}, cannot set to {not v}", field, k)

    if value is None:
        value = random.choice((True, False))
    return {"value": value}
```

Solvers of keywords (with sets, wildcards and regex), longs and ip addresses (with ipv4, ipv6 and cidr blocks) are way more complex, necessarily incomplete but proven correct for some definitions of _tested_.

### Generating the documents

Once constraints are solved and fields generated, document generation is the most simple and mechanical of all the steps.

Each document receives all its fields and their content from the corresponding constraints solution, the proper structure is established in form of nested Python dictionaries and lists.

Here in its simplified glory (from [detection_rules/events_emitter.py](../detection_rules/events_emitter.py))

```python
def docs_from_ast(cls, ast):
    docs = []
    for constraint in cls.emit(ast):
        doc = {}
        for field,value in constraint.resolve(cls.schema):
            if value is not None:
                deep_merge(doc, cls.emit_field(field, value))
        docs.append(doc)
    return docs
```

Note how a field might have value `None`, meaning that somewhere in the query it was demanded to be absent (eg. `process.pid == null`) and nowhere else the opposite was requested (it would have risen a conflict error), and therefore it's duly excluded from the generated document.

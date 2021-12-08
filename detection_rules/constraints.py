# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Helpers for value generation with constraints."""

import random
import string
import copy

class ConflictError(ValueError):
    def __init__(self, msg, field, name):
        super(ConflictError,self).__init__(f"Unsolvable constraint {name}: {field} ({msg})")

class solver:
    def __init__(self, field_type, *args):
        self.field_type = field_type
        self.valid_constraints = ("join_value", ) + args

    def __call__(self, func):
        def _solver(cls, field, value, constraints):
            join_values = []
            for k,v in constraints:
                if k not in self.valid_constraints:
                    raise NotImplementedError(f"Unsupported {self.field_type} constraint: {k}")
                if k == "join_value":
                    join_values.append(v)
            value = func(cls, field, value, constraints)
            for field,constraint in join_values:
                constraint.append_constraint(field, "==", value)
            return value
        return _solver

class Constraints:

    def __init__(self, field=None, name=None, value=None):
        self.constraints = {}
        if None not in (field, name):
            self.append_constraint(field, name, value)

    def clone(self):
        c = Constraints()
        c.constraints = copy.deepcopy(self.constraints)
        return c

    def append_constraint(self, field, name, value):
        if field not in self.constraints:
            self.constraints[field] = []
        self.constraints[field].append((name,value))

    def extend_constraints(self, field, constraints):
        if field not in self.constraints:
            self.constraints[field] = []
        self.constraints[field].extend(constraints)

    def __add__(self, other):
        c = self.clone()
        for field,constraints in other.constraints.items():
            c.extend_constraints(field, constraints)
        return c

    @classmethod
    @solver("boolean", "==", "!=")
    def solve_boolean_constraints(cls, field, value, constraints):
        for k,v in constraints:
            if k == "==":
                v = bool(v)
                if value is None or value == v:
                    value = v
                else:
                    raise ConflictError(f"{v} != {value}", field, k)
            elif k == "!=":
                v = bool(v)
                if value is None or value != v:
                    if value is None:
                        value = not v
                else:
                    raise ConflictError(f"{v} == {value}", field, k)

        if value is None:
            value = random.choice((True, False))
        return value

    @classmethod
    @solver("long", "==", "!=", ">=", "<=", ">", "<")
    def solve_long_constraints(cls, field, value, constraints):
        for k,v in constraints:
            if k == "==":
                v = int(v)
                if value is None or value == v:
                    value = v
                else:
                    raise ConflictError(f"{v} != {value}", field, k)
            elif k == "!=":
                v = int(v)
                if value is None or value != v:
                    if value is None:
                        value = v + 1
                else:
                    raise ConflictError(f"{v} == {value}", field, k)
            elif k == ">=":
                v = int(v)
                if value is None or value >= v:
                    if value is None:
                        value = v
                else:
                    raise ConflictError(f"{v} < {value}", field, k)
            elif k == "<=":
                v = int(v)
                if value is None or value <= v:
                    if value is None:
                        value = v
                else:
                    raise ConflictError(f"{v} > {value}", field, k)
            elif k == ">":
                v = int(v)
                if value is None or value > v:
                    if value is None:
                        value = v + 1
                else:
                    raise ConflictError(f"{v} <= {value}", field, k)
            elif k == "<":
                v = int(v)
                if value is None or value < v:
                    if value is None:
                        value = v - 1
                else:
                    raise ConflictError(f"{v} >= {value}", field, k)

        if value is None:
            value = random.randrange(2**16)
        return value

    @classmethod
    @solver("date", "==")
    def solve_date_constraints(cls, field, value, constraints):
        for k,v in constraints:
            if k == "==":
                if value is None or value == v:
                    value = v
                else:
                    raise ConflictError(f"{v} != {value}", field, k)

        if value is None:
            value = random.choice((True, False))
        return value

    @classmethod
    @solver("ip", "==")
    def solve_ip_constraints(cls, field, value, constraints):
        for k,v in constraints:
            if k == "==":
                if value is None or value == v:
                    value = v
                else:
                    raise ConflictError(f"{v} != {value}", field, k)

        if value == None:
            value = "1.1.1.1"
        return value

    @classmethod
    @solver("keyword", "==", "!=", "min_length", "allowed_chars")
    def solve_keyword_constraints(cls, field, value, constraints):
        allowed_chars = string.ascii_letters
        min_length = 3

        for k,v in constraints:
            if k == "min_length":
                if v >= min_length:
                    min_length = v
                else:
                    raise ConflictError(f"{v} < {min_length}", field, k)
            elif k == "allowed_chars":
                if set(v).issubset(set(allowed_chars)):
                    allowed_chars = v
                else:
                    raise ConflictError(f"{v} is not a subset of {allowed_chars}", field, k)
            elif k == "==":
                if type(value) == list:
                    value.append(v)
                elif value is None or value == v:
                    value = v
                else:
                    raise ConflictError(f"'{v}' != '{value}'", field, k)
            elif k == "!=":
                if value is None or value != v:
                    if value is None:
                        value = "!" + v
                else:
                    raise ConflictError(f"'{v}' == '{value}'", field, k)

        if value == None:
            value = "".join(random.choices(allowed_chars, k=min_length))
        return value

    @classmethod
    def solve_constraints(cls, field, constraints, schema):
        field_type = schema.get("type", "keyword")
        solver = getattr(cls, f"solve_{field_type}_constraints", None)
        if not solver:
            raise NotImplementedError(f"Constraints solver not implemented: {field_type}")
        if "array" in schema.get("normalize", []):
            value = []
        else:
            value = None
        return solver(field, value, constraints)

    def resolve(self, ecs_schema):
        for field,constraints in self.constraints.items():
            field_schema = ecs_schema.get(field, {})
            yield field, self.solve_constraints(field, constraints, field_schema)

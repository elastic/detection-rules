# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Helpers for value generation with constraints."""

import random
import string
import copy
from collections import namedtuple
import ipaddress

NumberLimits = namedtuple("NumberLimits", ["MIN", "MAX"])

# https://www.elastic.co/guide/en/elasticsearch/reference/current/number.html
LongLimits = NumberLimits(-2**63, 2**63-1)

ecs_constraints = {
    "pid": [(">", 0), ("<", 2**32)],
    "port": [(">", 0), ("<", 2**16)],
}

def get_ecs_constraints(field):
    if field in ecs_constraints:
        return ecs_constraints[field]
    field = field.split(".")[-1]
    if field in ecs_constraints:
        return ecs_constraints[field]
    return []

class ConflictError(ValueError):
    def __init__(self, msg, field, name=None):
        name = f" {name}" if name else ""
        super(ConflictError,self).__init__(f"Unsolvable constraints{name}: {field} ({msg})")

class solver:
    def __init__(self, field_type, *args):
        self.field_type = field_type
        self.valid_constraints = ("join_value", ) + args

    def __call__(self, func):
        def _solver(cls, field, value, constraints):
            join_values = []
            constraints = constraints + get_ecs_constraints(field)
            for k,v in constraints:
                if k not in self.valid_constraints:
                    raise NotImplementedError(f"Unsupported {self.field_type} constraint: {k}")
                if k == "join_value":
                    join_values.append(v)
            value = func(cls, field, value, constraints)
            for field,constraint in join_values:
                constraint.append_constraint(field, "==", value["value"])
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
        return {"value": value}

    @classmethod
    @solver("long", "==", "!=", ">=", "<=", ">", "<")
    def solve_long_constraints(cls, field, value, constraints):
        min_value = LongLimits.MIN
        max_value = LongLimits.MAX
        exclude_values = set()

        for k,v in constraints:
            if k == ">=":
                v = int(v)
                if min_value < v:
                    min_value = v
            elif k == "<=":
                v = int(v)
                if max_value > v:
                    max_value = v
            elif k == ">":
                v = int(v)
                if min_value < v + 1:
                    min_value = v + 1
            elif k == "<":
                v = int(v)
                if max_value > v - 1:
                    max_value = v - 1
        for k,v in constraints:
            if k == "==":
                v = int(v)
                if value is None or value == v:
                    value = v
                else:
                    raise ConflictError(f"is already {value}, cannot set to {v}", field, k)
            elif k == "!=":
                exclude_values.add(int(v))

        while min_value in exclude_values:
            min_value += 1
        while max_value in exclude_values:
            max_value -= 1
        if min_value > max_value:
            raise ConflictError(f"empty solution space, {min_value} <= x <= {max_value}", field)
        exclude_values = {v for v in exclude_values if v >= min_value and v <= max_value}
        if value is not None and value in exclude_values:
            if len(exclude_values) == 1:
                raise ConflictError(f"cannot be {exclude_values.pop()}", field)
            else:
                raise ConflictError(f"cannot be any of ({', '.join(str(v) for v in sorted(exclude_values))})", field)
        if value is not None and (value < min_value or value > max_value):
            raise ConflictError(f"out of boundary, {min_value} <= {value} <= {max_value}", field)
        while value is None or value in exclude_values:
            value = random.randint(min_value, max_value)
        return {"value": value, "min": min_value, "max": max_value}

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
        return {"value": value}

    @classmethod
    @solver("ip", "==", "!=", "in", "not in")
    def solve_ip_constraints(cls, field, value, constraints):
        include_nets = set()
        exclude_nets = set()
        exclude_addrs = set()

        for k,v in constraints:
            if k == "==":
                v = str(v)
                try:
                    v = ipaddress.ip_address(v)
                except ValueError:
                    pass
                else:
                    if value is not None and value != v:
                        raise ConflictError(f"is already {value}, cannot set to {v}", field, k)
                    value = v
                    continue
                try:
                    include_nets.add(ipaddress.ip_network(v))
                except ValueError:
                    raise ValueError(f"Not an IP address or network: {v}")
            elif k == "!=":
                v = str(v)
                try:
                    exclude_addrs.add(ipaddress.ip_address(v))
                    continue
                except ValueError:
                    pass
                try:
                    exclude_nets.add(ipaddress.ip_network(v))
                except ValueError:
                    raise ValueError(f"Not an IP address or network: {v}")
            elif k == "in":
                values = [v] if type(v) == str else v
                for v in values:
                    try:
                        include_nets.add(ipaddress.ip_network(str(v)))
                    except ValueError:
                        raise ValueError(f"Not an IP network: {str(v)}")
            elif k == "not in":
                values = [v] if type(v) == str else v
                for v in values:
                    try:
                        exclude_nets.add(ipaddress.ip_network(str(v)))
                    except ValueError:
                        raise ValueError(f"Not an IP network: {str(v)}")

        if include_nets & exclude_nets:
            raise ConflictError("net(s) both included and excluded: " +
                f"{', '.join(str(net) for net in sorted(include_nets & exclude_nets))}", field)
        if value is not None and value in exclude_addrs:
            if len(exclude_addrs) == 1:
                raise ConflictError(f"cannot be {exclude_addrs.pop()}", field)
            else:
                raise ConflictError(f"cannot be any of ({', '.join(str(v) for v in sorted(exclude_addrs))})", field)
        if value is not None and any(value in net for net in exclude_nets):
            if len(exclude_nets) == 1:
                raise ConflictError(f"cannot be in net {exclude_nets.pop()}", field)
            else:
                raise ConflictError(f"cannot be in any of nets ({', '.join(str(v) for v in sorted(exclude_nets))})", field)
        ip_versions = sorted(ip.version for ip in include_nets | exclude_nets | exclude_addrs) or [4]
        include_nets = sorted(include_nets, key=lambda x: (x.version, x))
        while value is None or value in exclude_addrs or any(value in net for net in exclude_nets):
            if include_nets:
                net = random.choice(include_nets)
                value = net[random.randrange(net.num_addresses)]
            else:
                bits = 128 if random.choice(ip_versions) == 6 else 32
                value = ipaddress.ip_address(random.randrange(1, 2**bits))
        return {"value": value.compressed}

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
        return {"value": value}

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
        return solver(field, value, constraints)["value"]

    def resolve(self, ecs_schema):
        for field,constraints in self.constraints.items():
            field_schema = ecs_schema.get(field, {})
            yield field, self.solve_constraints(field, constraints, field_schema)

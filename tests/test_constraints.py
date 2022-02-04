# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test constraints."""

import unittest

from tests.utils import *
from detection_rules.ecs import get_schema
from detection_rules.fuzzylib import fuzziness
from detection_rules.constraints import Constraints, Branch, LongLimits

ecs_schema = get_schema()

constraints_long = [
    ([
    ], {"value": -403652431857158667, "min": LongLimits.MIN, "max": LongLimits.MAX}),

    ([
    ], {"value": -403652431857158667, "min": LongLimits.MIN, "max": LongLimits.MAX}),

    ([
        ("!=", 0),
    ], {"value": -403652431857158667, "min": LongLimits.MIN, "max": LongLimits.MAX}),

    ([
        ("!=", 0),
        ("!=", 0),
    ], {"value": -403652431857158667, "min": LongLimits.MIN, "max": LongLimits.MAX}),

    ([
        ("!=", -403652431857158667),
    ], {"value": -7064441344606162906, "min": LongLimits.MIN, "max": LongLimits.MAX}),

    ([
        ("!=", -403652431857158667),
        ("!=", -7064441344606162906),
    ], {"value": -2206653630641079109, "min": LongLimits.MIN, "max": LongLimits.MAX}),

    ([
        ("==", 0),
    ], {"value": 0, "min": LongLimits.MIN, "max": LongLimits.MAX}),

    ([
        ("==", 0),
        ("==", 0),
    ], {"value": 0, "min": LongLimits.MIN, "max": LongLimits.MAX}),

    ([
        (">=", 0),
        ("<=", 0),
    ], {"value": 0, "min": 0, "max": 0}),

    ([
        (">", -1),
        ("<", 1),
    ], {"value": 0, "min": 0, "max": 0}),

    ([
        (">=", 10),
    ], {"value": 4409859803525838335, "min": 10, "max": LongLimits.MAX}),

    ([
        (">=", 10000),
    ], {"value": 4409859803525848325, "min": 10000, "max": LongLimits.MAX}),

    ([
        (">=", 10000),
        (">=", 10),
    ], {"value": 4409859803525848325, "min": 10000, "max": LongLimits.MAX}),

    ([
        (">=", 10),
        (">=", 10000),
    ], {"value": 4409859803525848325, "min": 10000, "max": LongLimits.MAX}),

    ([
        (">", 20),
    ], {"value": 4409859803525838346, "min": 21, "max": LongLimits.MAX}),

    ([
        (">", 20000),
    ], {"value": 4409859803525858326, "min": 20001, "max": LongLimits.MAX}),

    ([
        (">", 20000),
        (">", 20),
    ], {"value": 4409859803525858326, "min": 20001, "max": LongLimits.MAX}),

    ([
        (">", 20),
        (">", 20000),
    ], {"value": 4409859803525858326, "min": 20001, "max": LongLimits.MAX}),

    ([
        ("<=", 40),
    ], {"value": -403652431857158667, "min": LongLimits.MIN, "max": 40}),

    ([
        ("<=", 40000),
    ], {"value": -403652431857158667, "min": LongLimits.MIN, "max": 40000}),

    ([
        ("<=", 40000),
        ("<=", 40),
    ], {"value": -403652431857158667, "min": LongLimits.MIN, "max": 40}),

    ([
        ("<=", 40),
        ("<=", 40000),
    ], {"value": -403652431857158667, "min": LongLimits.MIN, "max": 40}),

    ([
        ("<", 80),
    ], {"value": -403652431857158667, "min": LongLimits.MIN, "max": 79}),

    ([
        ("<", 80000),
    ], {"value": -403652431857158667, "min": LongLimits.MIN, "max": 79999}),

    ([
        ("<", 80000),
        ("<", 80),
    ], {"value": -403652431857158667, "min": LongLimits.MIN, "max": 79}),

    ([
        ("<", 80),
        ("<", 80000),
    ], {"value": -403652431857158667, "min": LongLimits.MIN, "max": 79}),

    ([
        (">", 0),
        ("<=", 100),
    ] + [
        ("!=", x) for x in range(1, 100)
    ], {"value": 100, "min": 100, "max": 100}),

    ([
        (">=", 0),
        ("<", 100),
    ] + [
        ("!=", x) for x in range(1, 100)
    ], {"value": 0, "min": 0, "max": 0}),

    ([
        (">=", 0),
        ("<=", 100000),
    ] + [
        ("!=", x) for x in range(1, 100000)
    ], {"value": 0, "min": 0, "max": 100000}),
]

constraints_long_exceptions = [
    ([
        ("==", 0),
        ("==", 1),
    ], "Unsolvable constraints ==: test_var (is already 0, cannot set to 1)"),

    ([
        ("==", 1),
        ("==", 0),
    ], "Unsolvable constraints ==: test_var (is already 1, cannot set to 0)"),

    ([
        ("==", 0),
        ("!=", 0),
    ], "Unsolvable constraints: test_var (cannot be 0)"),

    ([
        ("!=", 0),
        ("==", 0),
    ], "Unsolvable constraints: test_var (cannot be 0)"),

    ([
        (">", 0),
        ("<", 0),
    ], "Unsolvable constraints: test_var (empty solution space, 1 <= x <= -1)"),

    ([
        ("<", 0),
        (">", 0),
    ], "Unsolvable constraints: test_var (empty solution space, 1 <= x <= -1)"),

    ([
        (">", 10),
        ("!=", 11),
        ("!=", 12),
        ("<", 13),
    ], "Unsolvable constraints: test_var (empty solution space, 13 <= x <= 10)"),

    ([
        ("!=", 10),
        ("!=", 11),
        ("!=", 12),
        ("==", 11),
    ], "Unsolvable constraints: test_var (cannot be any of (10, 11, 12))"),

    ([
        (">=", 0),
        ("<=", 100000),
        ("max_attempts", 10000),
    ] + [
        ("!=", x) for x in range(1, 100000)
    ], "Unsolvable constraints: test_var (attempts exausted: 10000)"),
]

constraints_ip = [
    ([
    ], {"value": "122.101.240.65"}),

    ([
        ("!=", "122.101.240.65"),
    ], {"value": "174.42.176.39"}),

    ([
        ("!=", "122.101.240.65"),
        ("!=", "174.42.176.39"),
    ], {"value": "110.236.17.111"}),

    ([
        ("==", "1.2.3.5"),
    ], {"value": "1.2.3.5"}),

    ([
        ("==", "122.110.117.0/24"),
    ], {"value": "122.110.117.244"}),

    ([
        ("in", "122.110.117.0/24"),
    ], {"value": "122.110.117.244"}),

    ([
        ("!=", "122.101.240.0/24"),
        ("!=", "174.42.176.0/24"),
    ], {"value": "110.236.17.111"}),

    ([
        ("not in", "122.101.240.0/24"),
        ("not in", "174.42.176.0/24"),
    ], {"value": "110.236.17.111"}),

    ([
        ("not in", ("122.101.240.0/24", "174.42.176.0/24")),
    ], {"value": "110.236.17.111"}),

    ([
        ("in", "127.0.0.0/8"),
    ], {"value": "127.244.203.224"}),

    ([
        ("in", "169.254.0.0/16"),
    ], {"value": "169.254.244.203"}),

    ([
        ("in", "10.0.0.0/8"),
        ("in", "192.168.0.0/16"),
    ], {"value": "192.168.244.203"}),

    ([
        ("in", ("10.0.0.0/8", "192.168.0.0/16")),
    ], {"value": "192.168.244.203"}),

    ([
        ("==", "::1"),
    ], {"value": "::1"}),

    ([
        ("in", "fe80::/64"),
    ], {"value": "fe80::8fd:f525:1b9:3e63"}),

    ([
        ("in", "fe80:a::/64"),
        ("in", "fe80:b::/64"),
        ("in", "fe80:c::/64"),
        ("in", "fe80:d::/64"),
    ], {"value": "fe80:d::8fd:f525:1b9:3e63"}),

    ([
        ("in", ("fe80:a::/64", "fe80:b::/64", "fe80:c::/64", "fe80:d::/64")),
    ], {"value": "fe80:d::8fd:f525:1b9:3e63"}),

    ([
        ("!=", "127.0.0.1"),
        ("!=", "::1"),
    ], {"value": "1df6:1006:ae2a:b026:b53:7e7c:7a65:f041"}),

    ([
        ("!=", "1df6:1006:ae2a:b026:b53:7e7c:7a65:f041"),
    ], {"value": "e66c:6e84:4aed:30c:6160:6436:db4f:fcbc"}),

    ([
        ("!=", "1df6:1006:ae2a:b026:b53:7e7c:7a65:f041"),
        ("!=", "e66c:6e84:4aed:30c:6160:6436:db4f:fcbc"),
    ], {"value": "38bf:b937:846b:5047:57:75f:8fd:f526"}),

    ([
        ("not in", "1df6::/16"),
        ("not in", "e66c::/16"),
    ], {"value": "38bf:b937:846b:5047:57:75f:8fd:f526"}),

    ([
        ("!=", "1df6::/16"),
        ("!=", "e66c::/16"),
    ], {"value": "38bf:b937:846b:5047:57:75f:8fd:f526"}),
]

constraints_ip_exceptions = [
    ([
        ("!=", "127.0.0.1"),
        ("==", "127.0.0.1"),
    ], "Unsolvable constraints: test_var (cannot be 127.0.0.1)"),

    ([
        ("==", "127.0.0.1"),
        ("!=", "127.0.0.1"),
    ], "Unsolvable constraints: test_var (cannot be 127.0.0.1)"),

    ([
        ("!=", "::1"),
        ("==", "::1"),
    ], "Unsolvable constraints: test_var (cannot be ::1)"),

    ([
        ("==", "::1"),
        ("!=", "::1"),
    ], "Unsolvable constraints: test_var (cannot be ::1)"),

    ([
        ("not in", "127.0.0.0/8"),
        ("==", "127.0.0.1"),
    ], "Unsolvable constraints: test_var (cannot be in net 127.0.0.0/8)"),

    ([
        ("not in", "::/96"),
        ("==", "::1"),
    ], "Unsolvable constraints: test_var (cannot be in net ::/96)"),

    ([
        ("not in", "127.0.0.0/8"),
        ("not in", "10.10.0.0/16"),
        ("==", "10.10.10.10"),
    ], "Unsolvable constraints: test_var (cannot be in any of nets (10.10.0.0/16, 127.0.0.0/8))"),

    ([
        ("not in", ("127.0.0.0/8", "10.10.0.0/16")),
        ("==", "10.10.10.10"),
    ], "Unsolvable constraints: test_var (cannot be in any of nets (10.10.0.0/16, 127.0.0.0/8))"),

    ([
        ("==", "127.0.0.1"),
        ("==", "1.2.3.4"),
    ], "Unsolvable constraints ==: test_var (is already 127.0.0.1, cannot set to 1.2.3.4)"),

    ([
        ("==", "::1"),
        ("==", "::2"),
    ], "Unsolvable constraints ==: test_var (is already ::1, cannot set to ::2)"),

    ([
        ("not in", "10.0.0.0/24"),
        ("in", "10.0.0.0/24"),
        ("not in", "10.0.1.0/24"),
        ("in", "10.0.1.0/24"),
    ], "Unsolvable constraints: test_var (net(s) both included and excluded: 10.0.0.0/24, 10.0.1.0/24)"),

    ([
        ("not in", ("10.0.0.0/24", "10.0.1.0/24")),
        ("in", ("10.0.0.0/24", "10.0.1.0/24")),
    ], "Unsolvable constraints: test_var (net(s) both included and excluded: 10.0.0.0/24, 10.0.1.0/24)"),

    ([
        ("in", "fe80::/64"),
        ("not in", "fe80::/64"),
    ], "Unsolvable constraints: test_var (net(s) both included and excluded: fe80::/64)"),
]

constraints_keyword = [
    ([
    ], {"value": "ycg"}),

    ([
    ], {"value": "ycg"}),

    ([
        ("!=", "ycg"),
    ], {"value": "Spa"}),

    ([
        ("!=", "ycg"),
        ("!=", "Spa"),
    ], {"value": "alZ"}),

    ([
        ("wildcard", "*.exe"),
    ], {"value": "cgspaalzajkedzp.exe"}),

    ([
        ("wildcard", "*.exe"),
        ("not wildcard", "cgsp*.exe"),
    ], {"value": "iusssrheshoebe.exe"}),

    ([
        ("wildcard", "*.exe"),
        ("not wildcard", "cgsp*.exe"),
        ("not wildcard", "iuss*.exe"),
    ], {"value": "xuqtfxhxlb.exe"}),

    ([
        ("==", "cmd.exe"),
    ], {"value": "cmd.exe"}),

    ([
        ("wildcard", "cmd.exe"),
    ], {"value": "cmd.exe"}),

    ([
        ("wildcard", "cmd.exe"),
        ("==", "cmd.exe"),
    ], {"value": "cmd.exe"}),

    ([
        ("wildcard", ("cmd.exe",)),
        ("==", "cmd.exe"),
    ], {"value": "cmd.exe"}),

    ([
        ("wildcard", ("cmd.exe", "powershell.exe")),
        ("==", "cmd.exe"),
    ], {"value": "cmd.exe"}),

    ([
        ("wildcard", ("cmd.exe", "powershell.exe", "regedit.exe")),
    ], {"value": "powershell.exe"}),
]

constraints_keyword_exceptions = [
    ([
        ("!=", "cmd.exe"),
        ("==", "cmd.exe"),
    ], "Unsolvable constraints: test_var (cannot be 'cmd.exe')"),

    ([
        ("==", "cmd.exe"),
        ("!=", "cmd.exe"),
    ], "Unsolvable constraints: test_var (cannot be 'cmd.exe')"),

    ([
        ("==", "cmd.exe"),
        ("not wildcard", "*.exe"),
    ], "Unsolvable constraints: test_var (cannot match '*.exe')"),

    ([
        ("wildcard", "*.exe"),
        ("not wildcard", "*.EXE"),
    ], "Unsolvable constraints: test_var (cannot match '*.exe')"),

    ([
        ("wildcard", "powershell.exe"),
        ("==", "cmd.exe"),
    ], "Unsolvable constraints ==: test_var (is already 'powershell.exe', cannot set to 'cmd.exe')"),

    ([
        ("wildcard", ("powershell.exe",)),
        ("==", "cmd.exe"),
    ], "Unsolvable constraints ==: test_var (is already 'powershell.exe', cannot set to 'cmd.exe')"),

    ([
        ("wildcard", "cmd.exe"),
        ("wildcard", "powershell.exe"),
    ], "Unsolvable constraints wildcard: test_var (is already 'cmd.exe', cannot set to 'powershell.exe')"),

    ([
        ("wildcard", ("cmd.exe", "powershell.exe")),
        ("==", "regedit.exe"),
    ], "Unsolvable constraints: test_var (does not match any of ('cmd.exe', 'powershell.exe'))"),

    ([
        ("wildcard", ("cmd.exe", "powershell.exe")),
        ("not wildcard", "*.exe"),
    ], "Unsolvable constraints: test_var (filtered wildcard(s): ('cmd.exe', 'powershell.exe') are filtered out by ('*.exe'))"),

    ([
        ("wildcard", ("cmd.exe", "powershell.exe")),
        ("not wildcard", ("*.exe", "cmd.*")),
    ], "Unsolvable constraints: test_var (filtered wildcard(s): ('cmd.exe', 'powershell.exe') are filtered out by ('*.exe', 'cmd.*'))"),
]

branch_products = [
    ([
        {"a": [(">=", 10), ("<=", 20)]},
    ],[
        {"b": [("==", 50)]},
    ],[
        {"a": [(">=", 10), ("<=", 20)], "b": [("==", 50)]},
    ]),

    ([
        {"a": [(">=", 10), ("<=", 20)]},
    ],[
        {"a": [("!=", 15)]},
    ],[
        {"a": [(">=", 10), ("<=", 20), ("!=", 15)]},
    ]),

    ([
        {"a": [(">=", 10), ("<=", 20)]},
    ],[
        {"a": [("!=", 15)]},
        {"a": [("!=", 16)]},
    ],[
        {"a": [(">=", 10), ("<=", 20), ("!=", 15)]},
        {"a": [(">=", 10), ("<=", 20), ("!=", 16)]},
    ]),

    ([
        {"a": [(">=", 10), ("<=", 20)]},
        {"a": [(">=", 100), ("<=", 200)]},
    ],[
        {"a": [("!=", 15)]},
    ],[
        {"a": [(">=", 10), ("<=", 20), ("!=", 15)]},
        {"a": [(">=", 100), ("<=", 200), ("!=", 15)]},
    ]),

    ([
        {"a": [(">=", 10), ("<=", 20)]},
        {"b": [("wildcard", ("one", "two"))]},
    ],[
        {"a": [("!=", 15)], "c": [("!=", None)]},
        {"b": [("not wildcard", "three")]},
    ],[
        {"a": [(">=", 10), ("<=", 20), ("!=", 15)], "c": [("!=", None)]},
        {"a": [(">=", 10), ("<=", 20)], "b": [("not wildcard", "three")]},
        {"b": [("wildcard", ("one", "two"))], "a": [("!=", 15)], "c": [("!=", None)]},
        {"b": [("wildcard", ("one", "two")), ("not wildcard", "three")]},
    ]),
]


class TestConstraints(SeededTestCase, unittest.TestCase):

    def subTest(self, *args, **kwargs):
        kwargs["seed"] = str(fuzziness())
        return super(TestConstraints, self).subTest(*args, **kwargs)

    def test_long(self):
        solver = Constraints.solve_long_constraints

        with fuzziness(1):
            for constraints, test_value in constraints_long:
                with self.subTest(constraints):
                    self.assertEqual(test_value, solver("test_var", None, constraints))

            for constraints, msg in constraints_long_exceptions:
                with self.subTest(constraints):
                    with self.assertRaises(ValueError, msg=msg) as cm:
                        self.assertEqual(None, solver("test_var", None, constraints))
                    self.assertEqual(msg, str(cm.exception))

    def test_ip(self):
        solver = Constraints.solve_ip_constraints

        with fuzziness(1):
            for constraints, test_value in constraints_ip:
                with self.subTest(constraints):
                    self.assertEqual(test_value, solver("test_var", None, constraints))

            for constraints, msg in constraints_ip_exceptions:
                with self.subTest(constraints):
                    with self.assertRaises(ValueError, msg=msg) as cm:
                        self.assertEqual(None, solver("test_var", None, constraints))
                    self.assertEqual(msg, str(cm.exception))

    def test_keyword(self):
        solver = Constraints.solve_keyword_constraints

        with fuzziness(1):
            for constraints, test_value in constraints_keyword:
                with self.subTest(constraints):
                    self.assertEqual(test_value, solver("test_var", None, constraints))

            for constraints, msg in constraints_keyword_exceptions:
                with self.subTest(constraints):
                    with self.assertRaises(ValueError, msg=msg) as cm:
                        self.assertEqual(None, solver("test_var", None, constraints))
                    self.assertEqual(msg, str(cm.exception))


class TestBranches(unittest.TestCase):

    def test_product(self):
        for a,b,c in branch_products:
            a = Branch([Constraints.from_dict(x) for x in a])
            b = Branch([Constraints.from_dict(x) for x in b])
            c = Branch([Constraints.from_dict(x) for x in c])
            with self.subTest(f"{a} * {b}"):
                self.assertEqual(a*b, c)

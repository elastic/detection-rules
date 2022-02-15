# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test constraints."""

import unittest

from tests.utils import *
from detection_rules.ecs import get_schema
from detection_rules.constraints import Constraints, Branch, LongLimits

ecs_schema = get_schema()

constraints_long = [
    ([
    ], {"value": -447795966606097183, "min": LongLimits.MIN, "max": LongLimits.MAX}),

    ([
    ], {"value": -447795966606097183, "min": LongLimits.MIN, "max": LongLimits.MAX}),

    ([
        ("!=", 0),
    ], {"value": -447795966606097183, "min": LongLimits.MIN, "max": LongLimits.MAX}),

    ([
        ("!=", 0),
        ("!=", 0),
    ], {"value": -447795966606097183, "min": LongLimits.MIN, "max": LongLimits.MAX}),

    ([
        ("!=", -447795966606097183),
    ], {"value": -391848440526208070, "min": LongLimits.MIN, "max": LongLimits.MAX}),

    ([
        ("!=", -447795966606097183),
        ("!=", -391848440526208070),
    ], {"value": -5754650716556900295, "min": LongLimits.MIN, "max": LongLimits.MAX}),

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
    ], {"value": 8255703960756213835, "min": 10, "max": LongLimits.MAX}),

    ([
        (">=", 10000),
    ], {"value": 8255703960756223825, "min": 10000, "max": LongLimits.MAX}),

    ([
        (">=", 10000),
        (">=", 10),
    ], {"value": 8255703960756223825, "min": 10000, "max": LongLimits.MAX}),

    ([
        (">=", 10),
        (">=", 10000),
    ], {"value": 8255703960756223825, "min": 10000, "max": LongLimits.MAX}),

    ([
        (">", 20),
    ], {"value": 8255703960756213846, "min": 21, "max": LongLimits.MAX}),

    ([
        (">", 20000),
    ], {"value": 8255703960756233826, "min": 20001, "max": LongLimits.MAX}),

    ([
        (">", 20000),
        (">", 20),
    ], {"value": 8255703960756233826, "min": 20001, "max": LongLimits.MAX}),

    ([
        (">", 20),
        (">", 20000),
    ], {"value": 8255703960756233826, "min": 20001, "max": LongLimits.MAX}),

    ([
        ("<=", 40),
    ], {"value": -1504411726168646672, "min": LongLimits.MIN, "max": 40}),

    ([
        ("<=", 40000),
    ], {"value": -1504411726168646672, "min": LongLimits.MIN, "max": 40000}),

    ([
        ("<=", 40000),
        ("<=", 40),
    ], {"value": -1504411726168646672, "min": LongLimits.MIN, "max": 40}),

    ([
        ("<=", 40),
        ("<=", 40000),
    ], {"value": -1504411726168646672, "min": LongLimits.MIN, "max": 40}),

    ([
        ("<", 80),
    ], {"value": -1504411726168646672, "min": LongLimits.MIN, "max": 79}),

    ([
        ("<", 80000),
    ], {"value": -1504411726168646672, "min": LongLimits.MIN, "max": 79999}),

    ([
        ("<", 80000),
        ("<", 80),
    ], {"value": -1504411726168646672, "min": LongLimits.MIN, "max": 79}),

    ([
        ("<", 80),
        ("<", 80000),
    ], {"value": -1504411726168646672, "min": LongLimits.MIN, "max": 79}),

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
    ], {"value": "107.31.65.130"}),

    ([
        ("!=", "107.31.65.130"),
    ], {"value": "229.172.181.141"}),

    ([
        ("!=", "107.31.65.130"),
        ("!=", "229.172.181.141"),
    ], {"value": "122.143.223.236"}),

    ([
        ("==", "1.2.3.5"),
    ], {"value": "1.2.3.5"}),

    ([
        ("==", "122.110.117.0/24"),
    ], {"value": "122.110.117.214"}),

    ([
        ("in", "122.110.117.0/24"),
    ], {"value": "122.110.117.214"}),

    ([
        ("!=", "107.31.65.0/24"),
        ("!=", "229.172.181.0/24"),
    ], {"value": "122.143.223.236"}),

    ([
        ("not in", "107.31.65.0/24"),
        ("not in", "229.172.181.0/24"),
    ], {"value": "122.143.223.236"}),

    ([
        ("not in", ("107.31.65.0/24", "229.172.181.0/24")),
    ], {"value": "122.143.223.236"}),

    ([
        ("in", "127.0.0.0/8"),
    ], {"value": "127.214.62.131"}),

    ([
        ("in", "169.254.0.0/16"),
    ], {"value": "169.254.214.62"}),

    ([
        ("in", "10.0.0.0/8"),
        ("in", "192.168.0.0/16"),
    ], {"value": "192.168.214.62"}),

    ([
        ("in", ("10.0.0.0/8", "192.168.0.0/16")),
    ], {"value": "192.168.214.62"}),

    ([
        ("==", "::1"),
    ], {"value": "::1"}),

    ([
        ("in", "fe80::/64"),
    ], {"value": "fe80::60a5:3ba:e6ea:94e4"}),

    ([
        ("in", "fe80:a::/64"),
        ("in", "fe80:b::/64"),
        ("in", "fe80:c::/64"),
        ("in", "fe80:d::/64"),
    ], {"value": "fe80:d::60a5:3ba:e6ea:94e4"}),

    ([
        ("in", ("fe80:a::/64", "fe80:b::/64", "fe80:c::/64", "fe80:d::/64")),
    ], {"value": "fe80:d::60a5:3ba:e6ea:94e4"}),

    ([
        ("!=", "127.0.0.1"),
        ("!=", "::1"),
    ], {"value": "aa79:ec58:8d14:2981:f18d:f2a6:6b1f:4182"}),

    ([
        ("!=", "aa79:ec58:8d14:2981:f18d:f2a6:6b1f:4182"),
    ], {"value": "7a8f:dfeb:60a5:3ba:e6ea:94e4:e5ac:b58d"}),

    ([
        ("!=", "aa79:ec58:8d14:2981:f18d:f2a6:6b1f:4182"),
        ("!=", "7a8f:dfeb:60a5:3ba:e6ea:94e4:e5ac:b58d"),
    ], {"value": "a92d:c839:9a9f:e89a:c443:b67a:770a:2cd8"}),

    ([
        ("not in", "aa79::/16"),
        ("not in", "7a8f::/16"),
    ], {"value": "a92d:c839:9a9f:e89a:c443:b67a:770a:2cd8"}),

    ([
        ("!=", "aa79::/16"),
        ("!=", "7a8f::/16"),
    ], {"value": "a92d:c839:9a9f:e89a:c443:b67a:770a:2cd8"}),
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
    ], {"value": "ZFy"}),

    ([
    ], {"value": "ZFy"}),

    ([
        ("!=", "ZFy"),
    ], {"value": "XIU"}),

    ([
        ("!=", "ZFy"),
        ("!=", "XIU"),
    ], {"value": "tkN"}),

    ([
        ("wildcard", "*.exe"),
    ], {"value": "xiutkni.exe"}),

    ([
        ("wildcard", "*.exe"),
        ("not wildcard", "xiut*.exe"),
    ], {"value": "ixtflezswueexp.exe"}),

    ([
        ("wildcard", "*.exe"),
        ("not wildcard", "xiut*.exe"),
        ("not wildcard", "ixtf*.exe"),
    ], {"value": "n.exe"}),

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
    ], {"value": "regedit.exe"}),
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

branch_fields = [
    ([
        {"a": [(">=", 10), ("<=", 20)], "b": [("!=", 0)]},
        {"c": [("==", "any")]},
    ],{
        "a", "b", "c",
    }),
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

    def test_long(self):
        solver = Constraints.solve_long_constraints

        for i, (constraints, test_value) in enumerate(constraints_long):
            with self.subTest(constraints, i=i):
                self.assertEqual(test_value, solver("test_var", None, constraints))

        for i, (constraints, msg) in enumerate(constraints_long_exceptions):
            with self.subTest(constraints, i=i):
                with self.assertRaises(ValueError, msg=msg) as cm:
                    self.assertEqual(None, solver("test_var", None, constraints))
                self.assertEqual(msg, str(cm.exception))

    def test_ip(self):
        solver = Constraints.solve_ip_constraints

        for i, (constraints, test_value) in enumerate(constraints_ip):
            with self.subTest(constraints, i=i):
                self.assertEqual(test_value, solver("test_var", None, constraints))

        for i, (constraints, msg) in enumerate(constraints_ip_exceptions):
            with self.subTest(constraints, i=i):
                with self.assertRaises(ValueError, msg=msg) as cm:
                    self.assertEqual(None, solver("test_var", None, constraints))
                self.assertEqual(msg, str(cm.exception))

    def test_keyword(self):
        solver = Constraints.solve_keyword_constraints

        for i, (constraints, test_value) in enumerate(constraints_keyword):
            with self.subTest(constraints, i=i):
                self.assertEqual(test_value, solver("test_var", None, constraints))

        for i, (constraints, msg) in enumerate(constraints_keyword_exceptions):
            with self.subTest(constraints, i=i):
                with self.assertRaises(ValueError, msg=msg) as cm:
                    self.assertEqual(None, solver("test_var", None, constraints))
                self.assertEqual(msg, str(cm.exception))


class TestBranches(unittest.TestCase):

    def test_fields(self):
        for a,fields in branch_fields:
            a = Branch([Constraints.from_dict(x) for x in a])
            with self.subTest(f"{a}"):
                self.assertEqual(fields, a.fields())

    def test_product(self):
        for a,b,c in branch_products:
            a = Branch([Constraints.from_dict(x) for x in a])
            b = Branch([Constraints.from_dict(x) for x in b])
            c = Branch([Constraints.from_dict(x) for x in c])
            with self.subTest(f"{a} * {b}"):
                self.assertEqual(a*b, c)

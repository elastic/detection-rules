# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test events emitter."""
import unittest
import random
import eql

from detection_rules.events_emitter import emitter

eql_event_docs = {
    """process where process.name == "regsvr32.exe"
    """: [
        {"event": {"category": "process"}, "process": {"name": "regsvr32.exe"}},
    ],

    """process where process.name != "regsvr32.exe"
    """: [
        {"event": {"category": "process"}, "process": {"name": "!regsvr32.exe"}},
    ],

    """process where process.pid == 0
    """: [
        {"event": {"category": "process"}, "process": {"pid": 0}},
    ],

    """process where process.pid != 0
    """: [
        {"event": {"category": "process"}, "process": {"pid": 1}},
    ],

    """process where process.pid >= 0
    """: [
        {"event": {"category": "process"}, "process": {"pid": 0}},
    ],

    """process where process.pid <= 0
    """: [
        {"event": {"category": "process"}, "process": {"pid": 0}},
    ],

    """process where process.pid > 0
    """: [
        {"event": {"category": "process"}, "process": {"pid": 1}},
    ],

    """process where process.pid < 0
    """: [
        {"event": {"category": "process"}, "process": {"pid": -1}},
    ],

    """process where process.code_signature.exists == true
    """: [
        {"event": {"category": "process"}, "process": {"code_signature": {"exists": True}}},
    ],

    """process where process.code_signature.exists != true
    """: [
        {"event": {"category": "process"}, "process": {"code_signature": {"exists": False}}},
    ],

    """any where network.protocol == "some protocol"
    """: [
        {"network": {"protocol": "some protocol"}},
    ],

    """process where process.name == "regsvr32.exe" and process.parent.name == "cmd.exe"
    """: [
        {"event": {"category": "process"}, "process": {"name": "regsvr32.exe", "parent": {"name": "cmd.exe"}}},
    ],

    """process where process.name == "regsvr32.exe" or process.parent.name == "cmd.exe"
    """: [
        {"event": {"category": "process"}, "process": {"name": "regsvr32.exe"}},
        {"event": {"category": "process"}, "process": {"parent": {"name": "cmd.exe"}}},
    ],

    """process where process.name == "regsvr32.exe" or process.name == "cmd.exe" or process.name == "powershell.exe"
    """: [
        {"event": {"category": "process"}, "process": {"name": "regsvr32.exe"}},
        {"event": {"category": "process"}, "process": {"name": "cmd.exe"}},
        {"event": {"category": "process"}, "process": {"name": "powershell.exe"}},
    ],

    """process where process.name in ("regsvr32.exe", "cmd.exe", "powershell.exe")
    """: [
        {"event": {"category": "process"}, "process": {"name": "regsvr32.exe"}},
        {"event": {"category": "process"}, "process": {"name": "cmd.exe"}},
        {"event": {"category": "process"}, "process": {"name": "powershell.exe"}},
    ],

    """process where process.name in ("regsvr32.exe", "cmd.exe") or process.name == "powershell.exe"
    """: [
        {"event": {"category": "process"}, "process": {"name": "regsvr32.exe"}},
        {"event": {"category": "process"}, "process": {"name": "cmd.exe"}},
        {"event": {"category": "process"}, "process": {"name": "powershell.exe"}},
    ],

    """process where process.name : "REG?*32.EXE"
    """: [
        {"event": {"category": "process"}, "process": {"name": "reg_32.exe"}},
    ],

    """process where event.type in ("start", "process_started") and process.args : "dump-keychain" and process.args : "-d"
    """: [
        {"event": {"category": "process", "type": ["start"]}, "process": {"args": ["-d", "dump-keychain"]}},
        {"event": {"category": "process", "type": ["process_started"]}, "process": {"args": ["-d", "dump-keychain"]}},
    ],
}

eql_event_exceptions = {
    """any where network.protocol == "some protocol" and network.protocol == "some other protocol"
    """:
        'Destination field already exists: network.protocol ("some other protocol" != "some protocol")',
}

eql_sequence_docs = {
    """sequence
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe"]
    """: [
        {"event": {"category": "process"}, "process": {"name": "cmd.exe"}},
        {"event": {"category": "process"}, "process": {"parent": {"name": "cmd.exe"}}},
    ],

    """sequence by user.id
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe"]
    """: [
        {"event": {"category": "process"}, "process": {"name": "cmd.exe"}, "user": {"id": "dMR"}},
        {"event": {"category": "process"}, "process": {"parent": {"name": "cmd.exe"}}, "user": {"id": "dMR"}},
    ],

    """sequence
        [process where process.name : "cmd.exe"] by user.id
        [process where process.parent.name : "cmd.exe"] by user.name
    """: [
        {"event": {"category": "process"}, "process": {"name": "cmd.exe"}, "user": {"id": "EZH"}},
        {"event": {"category": "process"}, "process": {"parent": {"name": "cmd.exe"}}, "user": {"name": "EZH"}},
    ],

    """sequence
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe" or process.name : "powershell.exe"]
    """: [
        {"event": {"category": "process"}, "process": {"name": "cmd.exe"}},
        {"event": {"category": "process"}, "process": {"parent": {"name": "cmd.exe"}}},
        {"event": {"category": "process"}, "process": {"name": "cmd.exe"}},
        {"event": {"category": "process"}, "process": {"name": "powershell.exe"}},
    ],

    """sequence by user.id
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe" or process.name : "powershell.exe"]
    """: [
        {"event": {"category": "process"}, "process": {"name": "cmd.exe"}, "user": {"id": "yAv"}},
        {"event": {"category": "process"}, "process": {"parent": {"name": "cmd.exe"}}, "user": {"id": "yAv"}},
        {"event": {"category": "process"}, "process": {"name": "cmd.exe"}, "user": {"id": "KQQ"}},
        {"event": {"category": "process"}, "process": {"name": "powershell.exe"}, "user": {"id": "KQQ"}},
    ],

    """sequence
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.name
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.parent.name
    """: [
        {"event": {"category": "process"}, "process": {"name": "cmd.exe"}},
        {"event": {"category": "process"}, "process": {"name": "cmd.exe", "parent": {"name": "cmd.exe"}}},
        {"event": {"category": "process"}, "process": {"name": "cmd.exe"}},
        {"event": {"category": "process"}, "process": {"name": "powershell.exe", "parent": {"name": "cmd.exe"}}},
        {"event": {"category": "process"}, "process": {"name": "powershell.exe"}},
        {"event": {"category": "process"}, "process": {"name": "cmd.exe", "parent": {"name": "powershell.exe"}}},
        {"event": {"category": "process"}, "process": {"name": "powershell.exe"}},
        {"event": {"category": "process"}, "process": {"name": "powershell.exe", "parent": {"name": "powershell.exe"}}},
    ],

    """sequence by user.id
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.name
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.parent.name
    """: [
        {"event": {"category": "process"}, "process": {"name": "cmd.exe"}, "user": {"id": "KbTNHP"}},
        {"event": {"category": "process"}, "process": {"name": "cmd.exe", "parent": {"name": "cmd.exe"}}, "user": {"id": "KbTNHP"}},
        {"event": {"category": "process"}, "process": {"name": "cmd.exe"}, "user": {"id": "xIPVPH"}},
        {"event": {"category": "process"}, "process": {"name": "powershell.exe", "parent": {"name": "cmd.exe"}}, "user": {"id": "xIPVPH"}},
        {"event": {"category": "process"}, "process": {"name": "powershell.exe"}, "user": {"id": "MKhQrp"}},
        {"event": {"category": "process"}, "process": {"name": "cmd.exe", "parent": {"name": "powershell.exe"}}, "user": {"id": "MKhQrp"}},
        {"event": {"category": "process"}, "process": {"name": "powershell.exe"}, "user": {"id": "tJNhXK"}},
        {"event": {"category": "process"}, "process": {"name": "powershell.exe", "parent": {"name": "powershell.exe"}}, "user": {"id": "tJNhXK"}},
    ],
}

class TestEventEmitter(unittest.TestCase):

    def test_eql_events(self):
        # make repeatable random choices
        random.seed(0xbadfab1e)

        with eql.parser.elasticsearch_syntax:
            for query, docs in eql_event_docs.items():
                with self.subTest(query):
                    self.assertEqual(docs, emitter.emit_events(eql.parse_query(query)))

            for query, msg in eql_event_exceptions.items():
                with self.subTest(query):
                    with self.assertRaises(ValueError, msg=msg):
                        emitter.emit_events(eql.parse_query(query))

    def test_eql_sequence(self):
        # make repeatable random choices
        random.seed(0xbadfab1e)

        with eql.parser.elasticsearch_syntax:
            for query, docs in eql_sequence_docs.items():
                with self.subTest(query):
                    self.assertEqual(docs, emitter.emit_events(eql.parse_query(query)))

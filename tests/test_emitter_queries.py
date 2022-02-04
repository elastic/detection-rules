# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test emitter with querie."""

import os
import eql
import unittest

from tests.utils import *
from detection_rules.events_emitter import emitter
from detection_rules import jupyter


eql_event_docs_mappings = {
    """process where process.name == "regsvr32.exe"
    """: {
        "properties": {
            "event": {"properties": {"category": {"type": "keyword"}}},
            "process": {"properties": {"name": {"type": "keyword"}}},
        },
    },

    """network where source.ip == "::1" or destination.ip == "::1"
    """: {
        "properties": {
            "event": {"properties": {"category": {"type": "keyword"}}},
            "destination": {"properties": {"ip": {"type": "ip"}}},
            "source": {"properties": {"ip": {"type": "ip"}}},
        },
    },

    """process where process.code_signature.exists == false and process.pid > 1024
    """: {
        "properties": {
            "event": {"properties": {"category": {"type": "keyword"}}},
            "process": {"properties": {"code_signature": {"properties": {"exists": {"type": "boolean"}}}, "pid": {"type": "long"}}},
        },
    },
}

eql_mono_branch_mono_doc = {
    """any where true
    """: [
        [{}],
    ],

    """any where not false
    """: [
        [{}],
    ],

    """any where not (true and false)
    """: [
        [{}],
    ],

    """any where not (false or false)
    """: [
        [{}],
    ],

    """network where source.port > 512 and source.port < 1024
    """: [
        [{"event": {"category": ["network"]}, "source": {"port": 794}}],
    ],

    """network where not (source.port < 512 or source.port > 1024)
    """: [
        [{"event": {"category": ["network"]}, "source": {"port": 1021}}],
    ],

    """network where destination.port not in (80, 443)
    """: [
        [{"event": {"category": ["network"]}, "destination": {"port": 7564}}],
    ],

    """network where not destination.port in (80, 443)
    """: [
        [{"event": {"category": ["network"]}, "destination": {"port": 246}}],
    ],

    """network where destination.port == 22 and destination.port in (80, 443) or destination.port == 25
    """: [
        [{"event": {"category": ["network"]}, "destination": {"port": 25}}],
    ],

    """process where process.name == "regsvr32.exe"
    """: [
        [{"event": {"category": ["process"]}, "process": {"name": "regsvr32.exe"}}],
    ],

    """process where process.name != "regsvr32.exe"
    """: [
        [{"event": {"category": ["process"]}, "process": {"name": "Bmc"}}],
    ],

    """process where process.pid != 0
    """: [
        [{"event": {"category": ["process"]}, "process": {"pid": 3009213395}}],
    ],

    """process where process.pid >= 0
    """: [
        [{"event": {"category": ["process"]}, "process": {"pid": 1706296503}}],
    ],

    """process where process.pid > 0
    """: [
        [{"event": {"category": ["process"]}, "process": {"pid": 2505219495}}],
    ],

    """process where process.code_signature.exists == true
    """: [
        [{"event": {"category": ["process"]}, "process": {"code_signature": {"exists": True}}}],
    ],

    """process where process.code_signature.exists != true
    """: [
        [{"event": {"category": ["process"]}, "process": {"code_signature": {"exists": False}}}],
    ],

    """any where network.protocol == "some protocol"
    """: [
        [{"network": {"protocol": "some protocol"}}],
    ],

    """any where process.pid == null
    """: [
        [{}],
    ],

    """any where not process.pid != null
    """: [
        [{}],
    ],

    """any where process.pid != null
    """: [
        [{"process": {"pid": 102799507}}],
    ],

    """any where not process.pid == null
    """: [
        [{"process": {"pid": 2584819203}}],
    ],

    """process where process.name == "regsvr32.exe" and process.parent.name == "cmd.exe"
    """: [
        [{"event": {"category": ["process"]}, "process": {"name": "regsvr32.exe", "parent": {"name": "cmd.exe"}}}],
    ],

    """process where process.name : ("*.EXE", "*.DLL")
    """: [
        [{"event": {"category": ["process"]}, "process": {"name": "leneqzksddgex.exe"}}],
    ],

    """network where destination.ip == "127.0.0.1"
    """: [
        [{"event": {"category": ["network"]}, "destination": {"ip": "127.0.0.1"}}],
    ],

    """network where cidrMatch(destination.ip, "10.0.0.0/8", "192.168.0.0/16")
    """: [
        [{"event": {"category": ["network"]}, "destination": {"ip": "10.77.153.19"}}],
    ],

    """network where not cidrMatch(destination.ip, "10.0.0.0/8", "192.168.0.0/16")
    """: [
        [{"event": {"category": ["network"]}, "destination": {"ip": "0.225.250.37"}}],
    ],

    """network where destination.ip == "::1"
    """: [
        [{"event": {"category": ["network"]}, "destination": {"ip": "::1"}}],
    ],

    """network where destination.ip == "822e::/16"
    """: [
        [{"event": {"category": ["network"]}, "destination": {"ip": "822e:f740:dcc5:503a:946f:261:2c07:f7a5"}}],
    ],
}

eql_multi_branch_mono_doc = {
    """network where not (source.port > 512 and source.port < 1024)
    """: [
        [{"event": {"category": ["network"]}, "source": {"port": 182}}],
        [{"event": {"category": ["network"]}, "source": {"port": 54422}}],
    ],

    """network where source.port > 512 or source.port < 1024
    """: [
        [{"event": {"category": ["network"]}, "source": {"port": 44925}}],
        [{"event": {"category": ["network"]}, "source": {"port": 516}}],
    ],

    """network where source.port < 2000 and (source.port > 512 or source.port > 1024)
    """: [
        [{"event": {"category": ["network"]}, "source": {"port":  1334}}],
        [{"event": {"category": ["network"]}, "source": {"port": 1034}}],
    ],

    """network where (source.port > 512 or source.port > 1024) and source.port < 2000
    """: [
        [{"event": {"category": ["network"]}, "source": {"port": 575}}],
        [{"event": {"category": ["network"]}, "source": {"port": 1158}}],
    ],

    """network where (source.port > 1024 or source.port < 2000) and (source.port < 4000 or source.port > 512)
    """: [
        [{"event": {"category": ["network"]}, "source": {"port": 1970}}],
        [{"event": {"category": ["network"]}, "source": {"port": 52226}}],
        [{"event": {"category": ["network"]}, "source": {"port": 692}}],
        [{"event": {"category": ["network"]}, "source": {"port": 1464}}],
    ],

    """network where destination.port in (80, 443)
    """: [
        [{"event": {"category": ["network"]}, "destination": {"port": 80}}],
        [{"event": {"category": ["network"]}, "destination": {"port": 443}}],
    ],

    """process where process.name == "regsvr32.exe" or process.parent.name == "cmd.exe"
    """: [
        [{"event": {"category": ["process"]}, "process": {"name": "regsvr32.exe"}}],
        [{"event": {"category": ["process"]}, "process": {"parent": {"name": "cmd.exe"}}}],
    ],

    """process where process.name == "regsvr32.exe" or process.name == "cmd.exe" or process.name == "powershell.exe"
    """: [
        [{"event": {"category": ["process"]}, "process": {"name": "regsvr32.exe"}}],
        [{"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}}],
        [{"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}}],
    ],

    """process where process.name in ("regsvr32.exe", "cmd.exe", "powershell.exe")
    """: [
        [{"event": {"category": ["process"]}, "process": {"name": "regsvr32.exe"}}],
        [{"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}}],
        [{"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}}],
    ],

    """process where process.name in ("regsvr32.exe", "cmd.exe") or process.name == "powershell.exe"
    """: [
        [{"event": {"category": ["process"]}, "process": {"name": "regsvr32.exe"}}],
        [{"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}}],
        [{"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}}],
    ],

    """process where event.type in ("start", "process_started") and process.args : "dump-keychain" and process.args : "-d"
    """: [
        [{"event": {"category": ["process"], "type": ["start"]}, "process": {"args": ["dump-keychain", "-d"]}}],
        [{"event": {"category": ["process"], "type": ["process_started"]}, "process": {"args": ["dump-keychain", "-d"]}}],
    ],
}

eql_mono_branch_multi_doc = {
    """sequence
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe"]
    """: [[
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}},
        {"event": {"category": ["process"]}, "process": {"parent": {"name": "cmd.exe"}}},
    ]],

    """sequence by user.id
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe"]
    """: [[
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}, "user": {"id": "klM"}},
        {"event": {"category": ["process"]}, "process": {"parent": {"name": "cmd.exe"}}, "user": {"id": "klM"}},
    ]],

    """sequence
        [process where process.name : "cmd.exe"] by user.id
        [process where process.parent.name : "cmd.exe"] by user.name
    """: [[
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}, "user": {"id": "fmC"}},
        {"event": {"category": ["process"]}, "process": {"parent": {"name": "cmd.exe"}}, "user": {"name": "fmC"}},
    ]],
}

eql_multi_branch_multi_doc = {
    """sequence
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe" or process.name : "powershell.exe"]
    """: [[
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}},
        {"event": {"category": ["process"]}, "process": {"parent": {"name": "cmd.exe"}}},
    ], [
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}},
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}},
    ]],

    """sequence by user.id
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe" or process.name : "powershell.exe"]
    """: [[
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}, "user": {"id": "pKP"}},
        {"event": {"category": ["process"]}, "process": {"parent": {"name": "cmd.exe"}}, "user": {"id": "pKP"}},
    ], [
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}, "user": {"id": "dYR"}},
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}, "user": {"id": "dYR"}},
    ]],

    """sequence
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.name
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.parent.name
    """: [[
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}},
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe", "parent": {"name": "cmd.exe"}}},
    ], [
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}},
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe", "parent": {"name": "cmd.exe"}}},
    ], [
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}},
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe", "parent": {"name": "powershell.exe"}}},
    ], [
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}},
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe", "parent": {"name": "powershell.exe"}}},
    ]],

    """sequence by user.id
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.name
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.parent.name
    """: [[
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}, "user": {"id": "aPd"}},
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe", "parent": {"name": "cmd.exe"}}, "user": {"id": "aPd"}},
    ], [
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}, "user": {"id": "aiW"}},
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe", "parent": {"name": "cmd.exe"}}, "user": {"id": "aiW"}},
    ], [
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}, "user": {"id": "tSw"}},
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe", "parent": {"name": "powershell.exe"}}, "user": {"id": "tSw"}},
    ], [
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}, "user": {"id": "JEL"}},
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe", "parent": {"name": "powershell.exe"}}, "user": {"id": "JEL"}},
    ]],
}

eql_exceptions = {
    """any where false
    """:
        "Cannot trigger with any document",

    """any where not true
    """:
        "Cannot trigger with any document",

    """any where not (true and true)
    """:
        "Cannot trigger with any document",

    """any where not (true or false)
    """:
        "Cannot trigger with any document",

    """any where process.pid == null and process.pid != null
    """:
        "Unsolvable constraints: process.pid (cannot be non-null)",

    """any where process.pid > 0 and process.pid == null
    """:
        "Unsolvable constraints: process.pid (cannot be null)",

    """any where process.name != null and process.name == null
    """:
        "Unsolvable constraints: process.name (cannot be null)",

    """any where process.name == "cmd.exe" and process.name == null
    """:
        "Unsolvable constraints: process.name (cannot be null)",

    """process where process.pid == 0
    """:
        "Unsolvable constraints: process.pid (out of boundary, 1 <= 0 <= 4294967295)",

    """process where process.pid <= 0
    """:
        "Unsolvable constraints: process.pid (empty solution space, 1 <= x <= 0)",

    """process where process.pid < 0
    """:
        "Unsolvable constraints: process.pid (empty solution space, 1 <= x <= -1)",

    """any where network.protocol == "http" and network.protocol == "https"
    """:
        "Unsolvable constraints ==: network.protocol (is already 'http', cannot set to 'https')",

    """network where destination.port == 22 and destination.port in (80, 443)
    """:
        "Cannot trigger with any document",

    """network where not (source.port > 512 or source.port < 1024)
    """:
        "Unsolvable constraints: source.port (empty solution space, 1024 <= x <= 512)",

    """sequence by process.name
        [process where process.name : "cmd.exe"]
        [process where process.name : "powershell.exe"]
    """:
        "Unsolvable constraints ==: process.name (is already 'powershell.exe', cannot set to 'cmd.exe')",

    """sequence
        [process where process.name : "cmd.exe"] by process.name
        [process where process.parent.name : "powershell.exe"] by process.parent.name
    """:
        "Unsolvable constraints ==: process.parent.name (is already 'powershell.exe', cannot set to 'cmd.exe')",

    """sequence by process.name
        [process where process.name == null]
        [process where process.name : "powershell.exe"]
    """:
        "Unsolvable constraints: process.name (cannot be non-null)",
}


class TestQueries(QueryTestCase, SeededTestCase, unittest.TestCase):
    maxDiff = None
    nb = jupyter.Notebook()
    nb.cells.append(jupyter.Markdown(
    """
        # Documents generation from test queries

        This Jupyter Notebook captures the unit test results of documents generation from queries.
        Here you can learn what kind of queries the emitter handles and the documents it generates.

        Curious about the inner workings? Read [here](signals_generation.md). Need help in using a Jupyter Notebook?
        Read [here](https://jupyter-notebook.readthedocs.io/en/stable/notebook.html#structure-of-a-notebook-document).
    """))

    @classmethod
    @nb.chapter("## Preliminaries")
    def setUpClass(cls, cells):
        super(TestQueries, cls).setUpClass()
        cells += [
            jupyter.Markdown("""
                This is an auxiliary cell, it prepares the environment for all the subsequent cells. It's also
                a simple example of emitter API usage.
            """),
            jupyter.Code("""
                import os; os.chdir('../..')  # use the repo's root as base for local modules import
                import eql
                from detection_rules.events_emitter import emitter

                def emit(query):
                    with eql.parser.elasticsearch_syntax:
                        try:
                            return emitter.emit_docs(eql.parse_query(query))
                        except Exception as e:
                            print(e)
            """),
            jupyter.Markdown("""
                ## How to read the test results

                If you opened this as freshly generated, the output cells content comes from the unit tests run and
                you can read it as a plain test report. Such content is generated in a controlled environment and is
                meant not to change between unit tests runs.
                The notebook itself does not run in such controlled environment therefore executing these cells, even
                if unmodified, will likely lead to different results each time.

                On the other hand, you can experiment and modify the queries in the input cells, check the results
                and, why not?, report any interesting finding. You can also add and remove cells at will.
            """),
        ]

    def test_mappings(self):
        with eql.parser.elasticsearch_syntax:
            for query, mappings in eql_event_docs_mappings.items():
                with self.subTest(query):
                    emitter.reset_mappings()
                    _ = emitter.emit_docs(eql.parse_query(query))
                    self.assertEqual(mappings, emitter.emit_mappings())

    @nb.chapter("## Mono-branch mono-document")
    def test_eql_mono_branch_mono_doc(self, cells):
        cells.append(jupyter.Markdown(
        """
            What follow are all queries that may trigger a signal just with a single _minimal matching document_,
            therefore at most one document is generated for each execution.

            You will notice that some queries actually generate multiple documents, this happens when
            the query is disjunctive (e.g. contains an _or_ operator). In these cases each of the generated
            documents is enough to trigger the signal but all were generated to prove that all the disjunction
            branches are correctly visited.
        """))
        with eql.parser.elasticsearch_syntax:
            for i, (query, docs) in enumerate(eql_mono_branch_mono_doc.items()):
                with self.subTest(query, i=i):
                    self.assertEqual(len(docs), 1)
                    self.assertEqual(len(docs[0]), 1)
                    self.assertQuery(query, docs)
                cells.append(self.QueryCell(query, docs))

    @nb.chapter("## Multi-branch mono-document")
    def test_eql_multi_branch_mono_doc(self, cells):
        cells.append(jupyter.Markdown(
        """
        """))
        with eql.parser.elasticsearch_syntax:
            for i, (query, docs) in enumerate(eql_multi_branch_mono_doc.items()):
                with self.subTest(query, i=i):
                    self.assertGreater(len(docs), 1)
                    for branch in docs:
                        self.assertEqual(len(branch), 1)
                    self.assertQuery(query, docs)
                cells.append(self.QueryCell(query, docs))

    @nb.chapter("## Mono-branch multi-document")
    def test_eql_mono_branch_multi_doc(self, cells):
        cells.append(jupyter.Markdown(
        """
            Following queries instead require multiple _minimal matching documents_, it's not only the content of
            a single document that is analyzed but also the relation with the subsequent ones. Therefore a senquence
            of documents, with the appropriate relations, is generated each time and all the documents in the sequence
            are required for the signal to be generated.
        """))
        with eql.parser.elasticsearch_syntax:
            for i, (query, docs) in enumerate(eql_mono_branch_multi_doc.items()):
                with self.subTest(query, i=i):
                    self.assertEqual(len(docs), 1)
                    self.assertGreater(len(docs[0]), 1)
                    self.assertQuery(query, docs)
                cells.append(self.QueryCell(query, docs))

    @nb.chapter("## Multi-branch multi-document")
    def test_eql_multi_branch_multi_doc(self, cells):
        cells.append(jupyter.Markdown(
        """
        """))
        with eql.parser.elasticsearch_syntax:
            for i, (query, docs) in enumerate(eql_multi_branch_multi_doc.items()):
                with self.subTest(query, i=i):
                    self.assertGreater(len(docs), 1)
                    for branch in docs:
                        self.assertGreater(len(branch), 1)
                    self.assertQuery(query, docs)
                cells.append(self.QueryCell(query, docs))

    @nb.chapter("## Error conditions")
    def test_eql_exceptions(self, cells):
        cells.append(jupyter.Markdown(
        """
            Not all the queries make sense, no documents can be generated for those that cannot logically be ever
            matched. In such cases an error is reported, as the following cells show.

            Here you can challenge the generation engine first hand and check that all the due errors are reported
            and make sense to you.
        """))
        with eql.parser.elasticsearch_syntax:
            for i, (query, msg) in enumerate(eql_exceptions.items()):
                with self.subTest(query, i=i):
                    with self.assertRaises(ValueError, msg=msg) as cm:
                        self.assertQuery(query, None)
                    self.assertEqual(msg, str(cm.exception))
                    cells.append(self.QueryCell(query, str(cm.exception), output_type="stream"))

    @nb.chapter("## Any oddities?")
    def test_unchanged(self, cells):
        cells.append(jupyter.Markdown(
        """
            Did you find anything odd reviewing the report or playing with the documents emitter?
            We are interested to know.
        """))
        assertReportUnchanged(self, self.nb, "documents_from_queries.ipynb")


@unittest.skipIf(os.getenv("TEST_SIGNALS_QUERIES", "0").lower() in ("0", "false", "no", ""), "Slow online test")
class TestSignalsQueries(SignalsTestCase, OnlineTestCase, SeededTestCase, unittest.TestCase):
    maxDiff = None
    nb = jupyter.Notebook()
    nb.cells.append(jupyter.Markdown(
    """
        # Alerts generation from test queries

        This report captures the unit test queries signals generation coverage.
        Here you can learn what queries are supported.
    """))

    def parse_from_queries(self, queries):
        rules = []
        asts = []
        for i,query in enumerate(queries):
            index_name = "{:s}-{:03d}".format(self.index_template, i)
            rules.append({
                "rule_id": "test_{:03d}".format(i),
                "risk_score": 17,
                "description": "Test rule {:03d}".format(i),
                "name": "Rule {:03d}".format(i),
                "index": [index_name],
                "interval": "3s",
                "from": "now-5m",
                "severity": "low",
                "type": "eql",
                "query": query,
                "language": "eql",
                "enabled": True,
                ".test_private": {},  # private test data, not sent to Kibana
            })
            asts.append(eql.parse_query(query))
        return rules, asts

    def test_queries(self):
        queries = tuple(eql_mono_branch_mono_doc) + tuple(eql_multi_branch_mono_doc) + \
                  tuple(eql_mono_branch_multi_doc) + tuple(eql_multi_branch_multi_doc)
        with eql.parser.elasticsearch_syntax:
            rules, asts = self.parse_from_queries(queries)
        pending = self.load_rules_and_docs(rules, asts)
        self.check_signals(rules, pending)
        assertReportUnchanged(self, self.nb, "alerts_from_queries.md")

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test events emitter."""

import os
import sys
import time
import unittest
import json
import eql
import hashlib
import textwrap
from pathlib import Path

from detection_rules.rule_loader import RuleCollection
from detection_rules.events_emitter import emitter
from detection_rules import utils, jupyter

jupyter.github_user = "cavokz"
jupyter.github_branch = "emit-events"

verbose = sum(arg.count('v') for arg in sys.argv if arg.startswith("-") and not arg.startswith("--"))

def _get_collection(var_name):
    var_value = os.getenv(var_name)
    rules_path = Path(var_value)
    if var_value.lower() in ("1", "true", "yes"):
        collection = RuleCollection.default()
    elif rules_path.exists() and rules_path.is_dir():
        collection = RuleCollection()
        collection.load_directory(rules_path)
    else:
        raise ValueError(f"path does not exist or is not a directory: {rules_path}")
    return collection

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

eql_event_docs_complete = {
    """any where true
    """: [
        {},
    ],

    """any where not false
    """: [
        {},
    ],

    """any where not (true and false)
    """: [
        {},
    ],

    """any where not (false or false)
    """: [
        {},
    ],

    """network where source.port > 512 and source.port < 1024
    """: [
        {"event": {"category": ["network"]}, "source": {"port": 859}},
    ],

    """network where not (source.port > 512 and source.port < 1024)
    """: [
        {"event": {"category": ["network"]}, "source": {"port": 236}},
        {"event": {"category": ["network"]}, "source": {"port": 19581}},
    ],

    """network where source.port > 512 or source.port < 1024
    """: [
        {"event": {"category": ["network"]}, "source": {"port": 44068}},
        {"event": {"category": ["network"]}, "source": {"port": 609}},
    ],

    """network where not (source.port < 512 or source.port > 1024)
    """: [
        {"event": {"category": ["network"]}, "source": {"port": 815}},
    ],

    """network where source.port < 2000 and (source.port > 512 or source.port > 1024)
    """: [
        {"event": {"category": ["network"]}, "source": {"port": 630}},
        {"event": {"category": ["network"]}, "source": {"port": 1957}},
    ],

    """network where (source.port > 512 or source.port > 1024) and source.port < 2000
    """: [
        {"event": {"category": ["network"]}, "source": {"port": 1105}},
        {"event": {"category": ["network"]}, "source": {"port": 1448}},
    ],

    """network where (source.port > 1024 or source.port < 2000) and (source.port < 4000 or source.port > 512)
    """: [
        {"event": {"category": ["network"]}, "source": {"port": 2567}},
        {"event": {"category": ["network"]}, "source": {"port": 569}},
        {"event": {"category": ["network"]}, "source": {"port": 61845}},
        {"event": {"category": ["network"]}, "source": {"port": 1670}},
    ],

    """network where destination.port in (80, 443)
    """: [
        {"event": {"category": ["network"]}, "destination": {"port": 80}},
        {"event": {"category": ["network"]}, "destination": {"port": 443}},
    ],

    """network where destination.port not in (80, 443)
    """: [
        {"event": {"category": ["network"]}, "destination": {"port": 35106}},
    ],

    """network where not destination.port in (80, 443)
    """: [
        {"event": {"category": ["network"]}, "destination": {"port": 58630}},
    ],

    """network where destination.port == 22 and destination.port in (80, 443) or destination.port == 25
    """: [
        {"event": {"category": ["network"]}, "destination": {"port": 25}},
    ],

    """process where process.name == "regsvr32.exe"
    """: [
        {"event": {"category": ["process"]}, "process": {"name": "regsvr32.exe"}},
    ],

    """process where process.name != "regsvr32.exe"
    """: [
        {"event": {"category": ["process"]}, "process": {"name": "pki"}},
    ],

    """process where process.pid != 0
    """: [
        {"event": {"category": ["process"]}, "process": {"pid": 1565416049}},
    ],

    """process where process.pid >= 0
    """: [
        {"event": {"category": ["process"]}, "process": {"pid": 2413373806}},
    ],

    """process where process.pid > 0
    """: [
        {"event": {"category": ["process"]}, "process": {"pid": 57239544}},
    ],

    """process where process.code_signature.exists == true
    """: [
        {"event": {"category": ["process"]}, "process": {"code_signature": {"exists": True}}},
    ],

    """process where process.code_signature.exists != true
    """: [
        {"event": {"category": ["process"]}, "process": {"code_signature": {"exists": False}}},
    ],

    """any where network.protocol == "some protocol"
    """: [
        {"network": {"protocol": "some protocol"}},
    ],

    """any where process.pid == null
    """: [
        {},
    ],

    """any where not process.pid != null
    """: [
        {},
    ],

    """any where process.pid != null
    """: [
        {"process": {"pid": 3617084353}},
    ],

    """any where not process.pid == null
    """: [
        {"process": {"pid": 3003800358}},
    ],

    """process where process.name == "regsvr32.exe" and process.parent.name == "cmd.exe"
    """: [
        {"event": {"category": ["process"]}, "process": {"name": "regsvr32.exe", "parent": {"name": "cmd.exe"}}},
    ],

    """process where process.name == "regsvr32.exe" or process.parent.name == "cmd.exe"
    """: [
        {"event": {"category": ["process"]}, "process": {"name": "regsvr32.exe"}},
        {"event": {"category": ["process"]}, "process": {"parent": {"name": "cmd.exe"}}},
    ],

    """process where process.name == "regsvr32.exe" or process.name == "cmd.exe" or process.name == "powershell.exe"
    """: [
        {"event": {"category": ["process"]}, "process": {"name": "regsvr32.exe"}},
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}},
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}},
    ],

    """process where process.name in ("regsvr32.exe", "cmd.exe", "powershell.exe")
    """: [
        {"event": {"category": ["process"]}, "process": {"name": "regsvr32.exe"}},
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}},
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}},
    ],

    """process where process.name in ("regsvr32.exe", "cmd.exe") or process.name == "powershell.exe"
    """: [
        {"event": {"category": ["process"]}, "process": {"name": "regsvr32.exe"}},
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}},
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}},
    ],

    """process where process.name : ("*.EXE", "*.DLL")
    """: [
        {"event": {"category": ["process"]}, "process": {"name": "hhkrsftx.dll"}},
    ],

    """process where event.type in ("start", "process_started") and process.args : "dump-keychain" and process.args : "-d"
    """: [
        {"event": {"category": ["process"], "type": ["start"]}, "process": {"args": ["dump-keychain", "-d"]}},
        {"event": {"category": ["process"], "type": ["process_started"]}, "process": {"args": ["dump-keychain", "-d"]}},
    ],

    """network where destination.ip == "127.0.0.1"
    """: [
        {"event": {"category": ["network"]}, "destination": {"ip": "127.0.0.1"}},
    ],

    """network where cidrMatch(destination.ip, "10.0.0.0/8", "192.168.0.0/16")
    """: [
        {"event": {"category": ["network"]}, "destination": {"ip": "192.168.129.181"}},
    ],

    """network where not cidrMatch(destination.ip, "10.0.0.0/8", "192.168.0.0/16")
    """: [
        {"event": {"category": ["network"]}, "destination": {"ip": "106.218.221.201"}},
    ],

    """network where destination.ip == "::1"
    """: [
        {"event": {"category": ["network"]}, "destination": {"ip": "::1"}},
    ],

    """network where destination.ip == "822e::/16"
    """: [
        {"event": {"category": ["network"]}, "destination": {"ip": "822e:d242:3361:b181:c4c:ee59:cfdb:60aa"}},
    ],
}

eql_sequence_docs_complete = {
    """sequence
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe"]
    """: [
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}},
        {"event": {"category": ["process"]}, "process": {"parent": {"name": "cmd.exe"}}},
    ],

    """sequence by user.id
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe"]
    """: [
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}, "user": {"id": "xgG"}},
        {"event": {"category": ["process"]}, "process": {"parent": {"name": "cmd.exe"}}, "user": {"id": "xgG"}},
    ],

    """sequence
        [process where process.name : "cmd.exe"] by user.id
        [process where process.parent.name : "cmd.exe"] by user.name
    """: [
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}, "user": {"id": "Eev"}},
        {"event": {"category": ["process"]}, "process": {"parent": {"name": "cmd.exe"}}, "user": {"name": "Eev"}},
    ],

    """sequence
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe" or process.name : "powershell.exe"]
    """: [
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}},
        {"event": {"category": ["process"]}, "process": {"parent": {"name": "cmd.exe"}}},
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}},
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}},
    ],

    """sequence by user.id
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe" or process.name : "powershell.exe"]
    """: [
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}, "user": {"id": "GuM"}},
        {"event": {"category": ["process"]}, "process": {"parent": {"name": "cmd.exe"}}, "user": {"id": "GuM"}},
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}, "user": {"id": "etd"}},
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}, "user": {"id": "etd"}},
    ],

    """sequence
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.name
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.parent.name
    """: [
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}},
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe", "parent": {"name": "cmd.exe"}}},
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}},
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe", "parent": {"name": "cmd.exe"}}},
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}},
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe", "parent": {"name": "powershell.exe"}}},
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}},
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe", "parent": {"name": "powershell.exe"}}},
    ],

    """sequence by user.id
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.name
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.parent.name
    """: [
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}, "user": {"id": "Tkx"}},
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe", "parent": {"name": "cmd.exe"}}, "user": {"id": "Tkx"}},
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}, "user": {"id": "REt"}},
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe", "parent": {"name": "cmd.exe"}}, "user": {"id": "REt"}},
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}, "user": {"id": "dLh"}},
        {"event": {"category": ["process"]}, "process": {"name": "cmd.exe", "parent": {"name": "powershell.exe"}}, "user": {"id": "dLh"}},
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}, "user": {"id": "Bvu"}},
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe", "parent": {"name": "powershell.exe"}}, "user": {"id": "Bvu"}},
    ],
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


def assertIdenticalFiles(tc, first, second):
    with open(first) as f:
        first_hash = hashlib.sha256(f.read().encode("utf-8")).hexdigest()
    with open(second) as f:
        second_hash = hashlib.sha256(f.read().encode("utf-8")).hexdigest()
    tc.assertEqual(first_hash, second_hash)


def assertReportUnchanged(tc, nb, report):
    filename = utils.get_path("tests", "reports", report)
    old_filename = "{:s}.old{:s}".format(*os.path.splitext(filename))
    new_filename = "{:s}.new{:s}".format(*os.path.splitext(filename))
    os.rename(filename, old_filename)
    jupyter.random.seed(report)
    nb.save(filename)
    os.rename(filename, new_filename)
    os.rename(old_filename, filename)
    with tc.subTest(os.path.join("tests", "reports", report)):
        assertIdenticalFiles(tc, filename, new_filename)
        os.unlink(new_filename)


class QueryTestCase:

    @classmethod
    def QueryCell(cls, query, docs, **kwargs):
        source = "emit('''\n    " + query.strip() + "\n''')"
        output = docs if type(docs) == str else "[" + ",\n".join(str(doc) for doc in docs) + "]"
        return jupyter.Code(source, output, **kwargs)

    def subTest(self, query):
        fuzziness = emitter.fuzziness()
        completeness = emitter.completeness()
        seed = f"{query} {completeness} {fuzziness}"
        return super(QueryTestCase, self).subTest(query, completeness=completeness, fuzziness=fuzziness, seed=seed)

    def assertQuery(self, query, docs):
        self.assertEqual(docs, emitter.emit_docs(eql.parse_query(query)))


class TestQueries(QueryTestCase, utils.SeededTestCase, unittest.TestCase):
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
        with eql.parser.elasticsearch_syntax, emitter.fuzziness(0), emitter.completeness(1):
            for query, mappings in eql_event_docs_mappings.items():
                with self.subTest(query):
                    emitter.reset_mappings()
                    _ = emitter.emit_docs(eql.parse_query(query))
                    self.assertEqual(mappings, emitter.emit_mappings())

    @nb.chapter("## Simple queries")
    def test_eql_events_complete(self, cells):
        cells.append(jupyter.Markdown(
        """
            What follow are all queries that may trigger a signal just with a single _minimal matching document_,
            therefore at most one document is generated for each execution.

            You will notice that some queries actually generate multiple documents, this happens when
            the query is disjunctive (e.g. contains an _or_ operator). In these cases each of the generated
            documents is enough to trigger the signal but all were generated to prove that all the disjunction
            branches are correctly visited.
        """))
        with eql.parser.elasticsearch_syntax, emitter.fuzziness(0), emitter.completeness(1):
            for query, docs in eql_event_docs_complete.items():
                with self.subTest(query):
                    self.assertQuery(query, docs)
                cells.append(self.QueryCell(query, docs))

    @nb.chapter("## Sequence queries")
    def test_eql_sequence_complete(self, cells):
        cells.append(jupyter.Markdown(
        """
            Following queries instead require multiple _minimal matching documents_, it's not only the content of
            a single document that is analyzed but also the relation with the subsequent ones. Therefore a senquence
            of documents, with the appropriate relations, is generated each time and all the documents in the sequence
            are required for the signal to be generated.
        """))
        with eql.parser.elasticsearch_syntax, emitter.fuzziness(0), emitter.completeness(1):
            for query, docs in eql_sequence_docs_complete.items():
                with self.subTest(query):
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
        with eql.parser.elasticsearch_syntax, emitter.fuzziness(0):
            for query, msg in eql_exceptions.items():
                with self.subTest(query):
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


class TestRules(QueryTestCase, utils.SeededTestCase, unittest.TestCase):
    maxDiff = None
    nb = jupyter.Notebook()
    nb.cells.append(jupyter.Markdown(
    """
        # Documents generation from detection rules

        This report captures the error reported while generating documents from detection rules. Here you
        can learn what rules are still problematic and for which no documents can be generated at the moment.

        Curious about the inner workings? Read [here](signals_generation.md).
    """))

    @classmethod
    def setUpClass(cls):
        super(TestRules, cls).setUpClass()

    def parse_from_collection(self, collection):
        asts = []
        rules = []
        errors = {}
        for rule in collection:
            try:
                asts.append(emitter.ast_from_rule(rule.contents.data))
                rules.append(rule)
            except Exception as e:
                errors.setdefault(str(e), []).append(rule)
                continue

        with self.nb.chapter("## Skipped rules") as cells:
            cells.append(None)
            for err in sorted(errors, key=lambda e: len(errors[e]), reverse=True):
                heading = [f"{len(errors[err])} rules:", ""]
                bullets = []
                for rule in sorted(errors[err], key=lambda r: r.contents.data.name):
                    path = rule.path.relative_to(utils.ROOT_DIR)
                    bullets.append(f"* [{rule.contents.data.name}](../../{path})")
                with self.nb.chapter(f"### {err}") as cells:
                    cells.append(jupyter.Markdown(heading + sorted(bullets)))

        return rules, asts

    def generate_docs(self, rules, asts):
        errors = {}
        for rule,ast in zip(rules, asts):
            try:
                _ = emitter.docs_from_ast(ast)
            except Exception as e:
                errors.setdefault(str(e), []).append(rule)
                continue

        with self.nb.chapter("## Generation errors") as cells:
            cells.append(None)
            for err in sorted(errors, key=lambda e: len(errors[e]), reverse=True):
                heading = [f"{len(errors[err])} rules:"]
                bullets = []
                for rule in sorted(errors[err], key=lambda r: r.contents.data.name):
                    path = rule.path.relative_to(utils.ROOT_DIR)
                    bullets.append(f"* [{rule.contents.data.name}](../../{path})")
                with self.nb.chapter(f"### {err}") as cells:
                    cells.append(jupyter.Markdown(heading + sorted(bullets)))

    def test_rules_collection(self):
        collection = RuleCollection.default()
        with eql.parser.elasticsearch_syntax:
            rules, asts = self.parse_from_collection(collection)
        self.generate_docs(rules, asts)

    def test_unchanged(self):
        assertReportUnchanged(self, self.nb, "documents_from_rules.md")


class OnlineTestCase:
    index_template = "detection-rules-ut"

    @classmethod
    def setUpClass(cls):
        from elasticsearch import Elasticsearch
        from elasticsearch.client import IndicesClient
        from detection_rules.kibana import Kibana

        es_url = os.getenv("TEST_ELASTICSEARCH_URL", "http://elastic:changeit@localhost:29650")
        cls.es = Elasticsearch(es_url)
        kbn_url = os.getenv("TEST_KIBANA_URL", "http://elastic:changeit@localhost:65290")
        cls.kbn = Kibana(kbn_url)

        if not cls.es.ping():
            raise unittest.SkipTest(f"Could not reach Elasticsearch: {es_url}")
        if not cls.kbn.ping():
            raise unittest.SkipTest(f"Could not reach Kibana: {kbn_url}")

        cls.es_indices = IndicesClient(cls.es)
        cls.kbn.create_siem_index()

    @classmethod
    def tearDownClass(cls):
        cls.es.close()
        del(cls.es)
        del(cls.kbn)
        del(cls.es_indices)

    def setUp(self):
        super(OnlineTestCase, self).setUp()

        self.kbn.delete_detection_engine_rules()

        if self.es_indices.exists_index_template(self.index_template):
            self.es_indices.delete_index_template(self.index_template)

        self.es_indices.delete(f"{self.index_template}-*")
        self.es.delete_by_query(".siem-signals-default-000001", body={"query": {"match_all": {}}})


class SignalsTestCase:

    def generate_docs_and_mappings(self, rules, asts):
        emitter.reset_mappings()

        bulk = []
        for rule, ast in sorted(zip(rules, asts), key=lambda x: x[0]["name"]):
            with self.subTest(rule["query"]):
                try:
                    for doc in emitter.docs_from_ast(ast):
                        bulk.append(json.dumps({"index": {"_index": rule["index"][0]}}))
                        bulk.append(json.dumps(doc))
                        if verbose > 2:
                            sys.stderr.write(json.dumps(doc, sort_keys=True) + "\n")
                            sys.stderr.flush()
                except Exception as e:
                    if verbose > 2:
                        sys.stderr.write(f"{str(e)}\n")
                        sys.stderr.flush()
                    continue
        return (bulk, emitter.emit_mappings())

    def load_rules_and_docs(self, rules, asts, batch_size=100):
        docs, mappings = self.generate_docs_and_mappings(rules, asts)

        template = {
            "index_patterns": [
                f"{self.index_template}-*"
            ],
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                },
                "mappings": mappings,
            },
        }
        self.es_indices.put_index_template(self.index_template, body=template)

        with self.nb.chapter("## Rejected documents") as cells:
            pos = 0
            while docs[pos:pos+batch_size]:
                ret = self.es.bulk("\n".join(docs[pos:pos+batch_size]))
                for i,item in enumerate(ret["items"]):
                    if item["index"]["status"] != 201:
                        cells.append(jupyter.Markdown(str(item['index'])))
                        if verbose > 1:
                            sys.stderr.write(f"{str(item['index'])}\n")
                            sys.stderr.flush()
                pos += batch_size

        pending = self.kbn.create_detection_engine_rules(rules)
        for rule, rule_id in zip(rules, pending):
            rule["id"] = rule_id
        return pending

    def wait_for_rules(self, pending, timeout=300, sleep=5):
        start = time.time()
        successful = {}
        failed = {}
        while (time.time() - start) < timeout:
            self.check_rules(pending, successful, failed)
            if verbose:
                sys.stderr.write(f"{len(pending)} ")
                sys.stderr.flush()
            if pending:
                time.sleep(sleep)
            else:
                break
        return successful, failed

    def check_rules(self, pending, successful, failed):
        statuses = self.kbn.find_detection_engine_rules_statuses(pending)
        for rule_id, rule_status in statuses.items():
            current_status = rule_status["current_status"]
            if current_status["last_success_at"]:
                del(pending[rule_id])
                successful[rule_id] = rule_status
            elif current_status["last_failure_at"]:
                del(pending[rule_id])
                failed[rule_id] = rule_status

    def check_docs(self, rule):
        try:
            ret = self.es.search(index=",".join(rule["index"]), body={"query": {"match_all": {}}})
        except Exception as e:
            if verbose > 1:
                sys.stderr.write(f"{str(e)}\n")
                sys.stderr.flush()
            return []
        return [hit["_source"] for hit in ret["hits"]["hits"]]

    def get_signals_per_rule(self):
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "must_not": [
                        { "exists": { "field": "signal.rule.building_block_type" }},
                    ]
                }
            },
            "aggs": {
                "signals_per_rule": {
                    "terms": {
                        "field": "signal.rule.id",
                        "size": 10000,
                    }
                }
            }
        }
        ret = self.kbn.search_detection_engine_signals(body)
        return {bucket["key"]: bucket["doc_count"] for bucket in ret["aggregations"]["signals_per_rule"]["buckets"]}

    @classmethod
    def QueryCell(cls, query, docs, **kwargs):
        source = textwrap.dedent(query.strip())
        output = docs if type(docs) == str else "[" + ",\n".join(str(doc) for doc in docs) + "]"
        return jupyter.Code(source, output, **kwargs)

    def report_rules(self, rules, rule_ids, title):
        with self.nb.chapter(f"## {title}") as cells:
            for rule in rules:
                if rule["id"] in rule_ids:
                    docs = self.check_docs(rule)
                    t0 = None
                    for doc in docs:
                        t0 = t0 or docs[0]["@timestamp"]
                        doc["@timestamp"] -= t0
                    cells.append(jupyter.Markdown(f"### {rule['name']}"))
                    cells.append(self.QueryCell(rule["query"], docs))
                    if type(rule_ids) == dict:
                        rule_status = rule_ids[rule["id"]].get("current_status", {})
                        failure_message = rule_status.get("last_failure_message", "").replace(rule["id"], "<i>&lt;redacted&gt;</i>")
                        if failure_message:
                            cells.append(jupyter.Markdown(f"SDE says:\n> {failure_message}"))

    def debug_rules(self, rules, rule_ids):
        lines = []
        for rule in rules:
            if rule["id"] in rule_ids:
                docs = self.check_docs(rule)
                lines.append("")
                lines.append("{:s}: {:s}".format(rule["id"], rule["name"]))
                lines.append(rule["query"].strip())
                lines.extend(json.dumps(doc, sort_keys=True) for doc in docs)
                if type(rule_ids) == dict:
                    rule_status = rule_ids[rule["id"]].get("current_status", {})
                    failure_message = rule_status.get("last_failure_message", "")
                    if failure_message:
                        lines.append("SDE says:")
                        lines.append(f"  {failure_message}")
        return "\n" + "\n".join(lines)

    def assertSignals(self, rules, rule_ids, msg):
        if rule_ids:
            self.report_rules(rules, rule_ids, msg)
        with self.subTest(msg):
            msg = None if verbose < 3 else self.debug_rules(rules, rule_ids)
            self.assertEqual(len(rule_ids), 0, msg=msg)

    def check_signals(self, rules, pending):
        successful, failed = self.wait_for_rules(pending)
        signals = self.get_signals_per_rule()

        unsuccessful = set(signals) - set(successful)
        too_few_signals = set(successful) - set(signals)
        too_many_signals = {rule_id for rule_id,doc_count in signals.items() if doc_count > 1}
        correct_signals = {rule_id for rule_id,doc_count in signals.items() if doc_count == 1}

        rules = sorted(rules, key=lambda rule: rule["name"])
        self.assertSignals(rules, failed, "Failed rules")
        self.assertSignals(rules, unsuccessful, "Unsuccessful rules with signals")
        self.assertSignals(rules, too_few_signals, "Rules with too few signals")
        self.assertSignals(rules, too_many_signals, "Rules with too many signals")
        #self.report_rules(rules, correct_signals, "Rules with the correct signals")


@unittest.skipIf(os.getenv("TEST_SIGNALS_QUERIES", "0").lower() in ("0", "false", "no", ""), "Slow online test")
class TestSignalsQueries(SignalsTestCase, OnlineTestCase, utils.SeededTestCase, unittest.TestCase):
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
            })
            asts.append(eql.parse_query(query))
        return rules, asts

    def test_queries(self):
        queries = tuple(eql_event_docs_complete) + tuple(eql_sequence_docs_complete)
        with eql.parser.elasticsearch_syntax:
            rules, asts = self.parse_from_queries(queries)
        with emitter.fuzziness(0), emitter.completeness(0):
            pending = self.load_rules_and_docs(rules, asts)
        self.check_signals(rules, pending)
        assertReportUnchanged(self, self.nb, "alerts_from_queries.md")


@unittest.skipIf(os.getenv("TEST_SIGNALS_RULES", "0").lower() in ("0", "false", "no", ""), "Slow online test")
class TestSignalsRules(SignalsTestCase, OnlineTestCase, utils.SeededTestCase, unittest.TestCase):
    maxDiff = None
    nb = jupyter.Notebook()
    nb.cells.append(jupyter.Markdown(
    """
        # Alerts generation from detection rules

        This report captures the detection rules signals generation coverage. Here you can
        learn what rules are supported and what not and why.

        Reasons for rules being not supported:
        * rule type is not EQL or query (e.g. ML, threshold)
        * query language is not EQL or Kuery (e.g. Lucene)
        * fields type mismatch (i.e. non-ECS field with incorrect type definition)
        * incorrect document generation

        Curious about the inner workings? Read [here](signals_generation.md).
    """))

    def parse_from_collection(self, collection):
        rules = []
        asts = []
        for i,rule in enumerate(collection):
            rule = rule.contents.data
            try:
                asts.append(emitter.ast_from_rule(rule))
            except:
                if verbose > 3:
                    sys.stderr.write(f"rule was skipped: type={rule.type}\n")
                    sys.stderr.flush()
                continue
            index_name = "{:s}-{:03d}".format(self.index_template, i)
            rules.append({
                "rule_id": rule.rule_id,
                "risk_score": rule.risk_score,
                "description": rule.description,
                "name": rule.name,
                "index": [index_name],
                "interval": "3s",
                "from": "now-5m",
                "severity": rule.severity,
                "type": rule.type,
                "query": rule.query,
                "language": rule.language,
                "enabled": True,
            })
        return rules, asts

    def test_rules(self):
        collection = _get_collection("TEST_SIGNALS_RULES")
        with eql.parser.elasticsearch_syntax:
            rules, asts = self.parse_from_collection(collection)
        with emitter.fuzziness(0), emitter.completeness(0):
            pending = self.load_rules_and_docs(rules, asts)
        self.check_signals(rules, pending)
        assertReportUnchanged(self, self.nb, "alerts_from_rules.md")

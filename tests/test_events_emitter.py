# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test events emitter."""

import os
import time
import unittest
import random
import json
from warnings import warn
import eql

from detection_rules.rule_loader import RuleCollection
from detection_rules.events_emitter import emitter

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

    """process where process.code_signature.exists == false and process.pid == 0
    """: {
        "properties": {
            "event": {"properties": {"category": {"type": "keyword"}}},
            "process": {"properties": {"code_signature": {"properties": {"exists": {"type": "boolean"}}}, "pid": {"type": "long"}}},
        },
    },
}

eql_event_docs_complete = {
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

    """process where process.name : ("*.EXE", "*.DLL")
    """: [
        {"event": {"category": "process"}, "process": {"name": "4pp7h.exe"}},
        {"event": {"category": "process"}, "process": {"name": "0gwcwq8s9dic.dll"}},
    ],

    """process where event.type in ("start", "process_started") and process.args : "dump-keychain" and process.args : "-d"
    """: [
        {"event": {"category": "process", "type": ["start"]}, "process": {"args": ["dump-keychain", "-d"]}},
        {"event": {"category": "process", "type": ["process_started"]}, "process": {"args": ["dump-keychain", "-d"]}},
    ],
}

eql_sequence_docs_complete = {
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
        {"event": {"category": "process"}, "process": {"name": "cmd.exe"}, "user": {"id": "xgG"}},
        {"event": {"category": "process"}, "process": {"parent": {"name": "cmd.exe"}}, "user": {"id": "xgG"}},
    ],

    """sequence
        [process where process.name : "cmd.exe"] by user.id
        [process where process.parent.name : "cmd.exe"] by user.name
    """: [
        {"event": {"category": "process"}, "process": {"name": "cmd.exe"}, "user": {"id": "Eev"}},
        {"event": {"category": "process"}, "process": {"parent": {"name": "cmd.exe"}}, "user": {"name": "Eev"}},
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
        {"event": {"category": "process"}, "process": {"name": "cmd.exe"}, "user": {"id": "GuM"}},
        {"event": {"category": "process"}, "process": {"parent": {"name": "cmd.exe"}}, "user": {"id": "GuM"}},
        {"event": {"category": "process"}, "process": {"name": "cmd.exe"}, "user": {"id": "etd"}},
        {"event": {"category": "process"}, "process": {"name": "powershell.exe"}, "user": {"id": "etd"}},
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
        {"event": {"category": "process"}, "process": {"name": "cmd.exe"}, "user": {"id": "TkxREt"}},
        {"event": {"category": "process"}, "process": {"name": "cmd.exe", "parent": {"name": "cmd.exe"}}, "user": {"id": "TkxREt"}},
        {"event": {"category": "process"}, "process": {"name": "cmd.exe"}, "user": {"id": "dLhBvu"}},
        {"event": {"category": "process"}, "process": {"name": "powershell.exe", "parent": {"name": "cmd.exe"}}, "user": {"id": "dLhBvu"}},
        {"event": {"category": "process"}, "process": {"name": "powershell.exe"}, "user": {"id": "UHxpew"}},
        {"event": {"category": "process"}, "process": {"name": "cmd.exe", "parent": {"name": "powershell.exe"}}, "user": {"id": "UHxpew"}},
        {"event": {"category": "process"}, "process": {"name": "powershell.exe"}, "user": {"id": "lKcSwh"}},
        {"event": {"category": "process"}, "process": {"name": "powershell.exe", "parent": {"name": "powershell.exe"}}, "user": {"id": "lKcSwh"}},
    ],
}

eql_exceptions = {
    """any where network.protocol == "http" and network.protocol == "https"
    """:
        'Destination field already exists: network.protocol ("https" != "http")',

    """sequence by process.name
        [process where process.name : "cmd.exe"]
        [process where process.name : "powershell.exe"]
    """:
        'ValueError: Destination field already exists: process.name ("powershell.exe" != "cmd.exe")',

    """sequence
        [process where process.name : "cmd.exe"] by process.name
        [process where process.parent.name : "powershell.exe"] by process.parent.name
    """:
        'ValueError: Destination field already exists: process.parent.name ("powershell.exe" != "cmd.exe")',
}


class TestCaseSeed:
    """Make Emitter repeat the same random choices."""

    def setUp(self):
        self.random_state = random.getstate()

    def tearDown(self):
        random.setstate(self.random_state)

    def subTest(self, query):
        fuzziness = emitter.fuzziness()
        completeness = emitter.completeness()
        random.seed(f"{query} {completeness} {fuzziness}")
        return super(TestCaseSeed, self).subTest(query, completeness=completeness, fuzziness=fuzziness)


class TestEventEmitter(TestCaseSeed, unittest.TestCase):

    def test_mappings(self):
        with eql.parser.elasticsearch_syntax, emitter.fuzziness(0), emitter.completeness(1):
            for query, mappings in eql_event_docs_mappings.items():
                with self.subTest(query):
                    emitter.reset_mappings()
                    _ = emitter.emit_events(eql.parse_query(query))
                    self.assertEqual(mappings, emitter.emit_mappings())

    def test_eql_exceptions(self):
        with eql.parser.elasticsearch_syntax, emitter.fuzziness(0):
            for query, msg in eql_exceptions.items():
                with self.subTest(query):
                    with self.assertRaises(ValueError, msg=msg):
                        emitter.emit_events(eql.parse_query(query))

    def test_eql_events_complete(self):
        with eql.parser.elasticsearch_syntax, emitter.fuzziness(0), emitter.completeness(1):
            for query, docs in eql_event_docs_complete.items():
                with self.subTest(query):
                    self.assertEqual(docs, emitter.emit_events(eql.parse_query(query)))

    def test_eql_sequence_complete(self):
        with eql.parser.elasticsearch_syntax, emitter.fuzziness(0), emitter.completeness(1):
            for query, docs in eql_sequence_docs_complete.items():
                with self.subTest(query):
                    self.assertEqual(docs, emitter.emit_events(eql.parse_query(query)))

class TestCaseOnline:
    index_template = "detection-rules-ut"

    @classmethod
    def setUpClass(cls):
        from elasticsearch import Elasticsearch
        from elasticsearch.client import IndicesClient
        from detection_rules.kibana import Kibana

        es_url = os.getenv("TEST_ELASTICSEARCH_URL", "http://elastic:changeit@localhost:9200")
        cls.es = Elasticsearch(es_url)
        kbn_url = os.getenv("TEST_KIBANA_URL", "http://elastic:changeit@localhost:5601")
        cls.kbn = Kibana(kbn_url)

        if not cls.es.ping():
            raise RuntimeError("Elasticsearch is not ready")
        res = cls.kbn.task_manager_health()
        if res.status_code != 200:
            raise RuntimeError(f"Kibana is not ready: {res.json()}")
        res = cls.kbn.create_siem_index()
        if res.status_code != 200:
            raise RuntimeError(f"Could not create SIEM index: {res.json()}")

        cls.es_indices = IndicesClient(cls.es)

    @classmethod
    def tearDownClass(cls):
        cls.es.close()
        del(cls.es)
        del(cls.kbn)
        del(cls.es_indices)

    def setUp(self):
        super(TestCaseOnline, self).setUp()

        res = self.kbn.delete_detection_engine_rules()
        if res.status_code != 200:
            raise RuntimeError(f"Could not reset rules: {res.json()}")

        if self.es_indices.exists_index_template(self.index_template):
            self.es_indices.delete_index_template(self.index_template)

        self.es_indices.delete(f"{self.index_template}-*")
        self.es.delete_by_query(".siem-signals-default-000001", body={"query": {"match_all": {}}})


skip_alerts_test = os.getenv("TEST_ALERTS", "0").lower() not in ("1", "true")
@unittest.skipIf(skip_alerts_test, "Slow online test")
class TestAlerts(TestCaseOnline, TestCaseSeed, unittest.TestCase):

    def get_rules_from_queries(self, queries):
        rules = []
        ast_nodes = []
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
        return rules

    def generate_docs(self, rules, ast_nodes):
        emitter.reset_mappings()
        emitter.add_mappings_field("@timestamp")
        emitter.add_mappings_field("ecs.version")
        emitter.add_mappings_field("rule.name")

        bulk = []
        for rule, ast_node in zip(rules, ast_nodes):
            with self.subTest(rule["query"]):
                try:
                    for doc in emitter.emit_events(ast_node):
                        doc.update({
                            "@timestamp": int(time.time() * 1000),
                            "ecs": {"version": emitter.ecs_version},
                            "rule": {"name": rule["name"]},
                        })
                        bulk.append(json.dumps({"index": {"_index": rule["index"][0]}}))
                        bulk.append(json.dumps(doc))
                except Exception as e:
                    warn(str(e))
        return (bulk, emitter.emit_mappings())

    def alerts_gen(self, rules, ast_nodes, batch_size=100):
        docs, mappings = self.generate_docs(rules, ast_nodes)

        template = {
            "index_patterns": [f"{self.index_template}-*"],
            "template": {"mappings": mappings},
        }
        self.es_indices.put_index_template(self.index_template, body=template)

        pos = 0
        while docs[pos:pos+batch_size]:
            ret = self.es.bulk("\n".join(docs[pos:pos+batch_size]))
            for item in ret["items"]:
                if item["index"]["status"] != 201:
                    warn(str(item["index"]))
            pos += batch_size

        res = self.kbn.create_detection_engine_rules(rules)
        self.assertEqual(200, res.status_code)

    def test_eql_events_complete(self):
        rules = self.get_rules_from_queries(eql_event_docs_complete)
        with eql.parser.elasticsearch_syntax:
            ast_nodes = [eql.parse_query(query) for query in eql_event_docs_complete]
        with emitter.fuzziness(0), emitter.completeness(1):
            self.alerts_gen(rules, ast_nodes)

    def test_eql_sequence_complete(self):
        rules = self.get_rules_from_queries(eql_sequence_docs_complete)
        with eql.parser.elasticsearch_syntax:
            ast_nodes = [eql.parse_query(query) for query in eql_sequence_docs_complete]
        with emitter.fuzziness(0), emitter.completeness(1):
            self.alerts_gen(rules, ast_nodes)

    def get_rules_from_collection(self, collection):
        rules = []
        ast_nodes = []
        for i,rule in enumerate(collection):
            rule = rule.contents.data
            if rule.type == "eql":
                ast_nodes.append(rule.validator.ast)
            elif rule.type == "query" and rule.language == "kuery":
                ast_nodes.append(rule.validator.to_eql())
            else:
                warn(f"rule was skipped: type={rule.type}")
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
        return rules, ast_nodes

    def test_collection(self):
        with eql.parser.elasticsearch_syntax:
            rules, ast_nodes = self.get_rules_from_collection(RuleCollection.default())
        with emitter.fuzziness(0), emitter.completeness(1):
            self.alerts_gen(rules, ast_nodes)

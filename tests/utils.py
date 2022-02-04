# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test case mixin classes."""

import os
import sys
import time
import json
import random
import hashlib
import textwrap
import itertools
import eql

from detection_rules import utils, jupyter
from detection_rules.events_emitter import emitter

__all__ = (
    "SeededTestCase",
    "QueryTestCase",
    "OnlineTestCase",
    "SignalsTestCase",
    "assertReportUnchanged",
)

verbose = sum(arg.count('v') for arg in sys.argv if arg.startswith("-") and not arg.startswith("--"))

jupyter.github_user = "cavokz"
jupyter.github_branch = "emit-events"

def get_rule_by_id(rules, rule_id):
    for rule in rules:
        if rule["id"] == rule_id:
            return rule
    raise KeyError(f"cannot to find rule by id: {rule_id}")

def get_rule_test_data(rules, rule_id):
    return get_rule_by_id(rules, rule_id)[".test_private"]

def filter_out_test_data(rules):
    return [{k:v for k,v in rule.items() if k != ".test_private"} for rule in rules]

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


class SeededTestCase:
    """Make repeatable random choices in unit tests."""

    @classmethod
    def setUpClass(cls):
        cls.__saved_state = random.getstate()
        random.seed("setUpClass")
        super(SeededTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        random.seed("tearDownClass")
        super(SeededTestCase, cls).tearDownClass()
        random.setstate(cls.__saved_state)

    def setUp(self):
        random.seed("setUp")
        super(SeededTestCase, self).setUp()

    def tearDown(self):
        random.seed("tearDown")
        super(SeededTestCase, self).tearDown()

    def subTest(self, *args, **kwargs):
        random.seed(kwargs.pop("seed", "subTest"))
        return super(SeededTestCase, self).subTest(*args, **kwargs)


class QueryTestCase:

    @classmethod
    def QueryCell(cls, query, output, **kwargs):
        source = "emit('''\n    " + query.strip() + "\n''')"
        if type(output) != str:
            output = "[[" + "],\n [".join(",\n  ".join(str(doc) for doc in branch) for branch in output) + "]]"
        return jupyter.Code(source, output, **kwargs)

    def subTest(self, query, **kwargs):
        fuzziness = emitter.fuzziness()
        completeness = emitter.completeness()
        seed = f"{query} {completeness} {fuzziness}"
        return super(QueryTestCase, self).subTest(query, **kwargs, completeness=completeness, fuzziness=fuzziness, seed=seed)

    def assertQuery(self, query, docs):
        self.assertEqual(docs, emitter.emit_docs(eql.parse_query(query)))


class OnlineTestCase:
    """Use Elasticsearch and Kibana in unit tests."""
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
    """Generate documents, load rules and documents, check triggered signals in unit tests."""

    def generate_docs_and_mappings(self, rules, asts):
        emitter.reset_mappings()

        bulk = []
        for rule, ast in sorted(zip(rules, asts), key=lambda x: x[0]["name"]):
            with self.subTest(rule["query"]):
                try:
                    branches = emitter.docs_from_ast(ast)
                except Exception as e:
                    rule["enabled"] = False
                    if verbose > 2:
                        sys.stderr.write(f"{str(e)}\n")
                        sys.stderr.flush()
                    continue

                rule[".test_private"]["branch_count"] = len(branches)
                for doc in itertools.chain(*branches):
                    bulk.append(json.dumps({"index": {"_index": rule["index"][0]}}))
                    bulk.append(json.dumps(doc))
                    if verbose > 2:
                        sys.stderr.write(json.dumps(doc, sort_keys=True) + "\n")
                        sys.stderr.flush()
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

        ret = self.kbn.create_detection_engine_rules(filter_out_test_data(rules))
        pending = {}
        for rule, rule_id in zip(rules, ret):
            rule["id"] = rule_id
            if rule["enabled"]:
                pending[rule_id] = ret[rule_id]
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

    def get_signals_per_rule(self, rules):
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
        signals = {}
        for bucket in ret["aggregations"]["signals_per_rule"]["buckets"]:
            branch_count = get_rule_test_data(rules, bucket["key"])["branch_count"]
            signals[bucket["key"]] = (bucket["doc_count"], branch_count)
        return signals

    @classmethod
    def QueryCell(cls, query, docs, **kwargs):
        source = textwrap.dedent(query.strip())
        output = docs if type(docs) == str else "[" + ",\n ".join(str(doc) for doc in docs) + "]"
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
        signals = self.get_signals_per_rule(rules)

        unsuccessful = set(signals) - set(successful)
        no_signals = set(successful) - set(signals)
        too_few_signals = {rule_id for rule_id,(signal_count,branch_count) in signals.items() if signal_count < branch_count}
        correct_signals = {rule_id for rule_id,(signal_count,branch_count) in signals.items() if signal_count == branch_count}
        too_many_signals = {rule_id for rule_id,(signal_count,branch_count) in signals.items() if signal_count > branch_count}

        rules = sorted(rules, key=lambda rule: rule["name"])
        self.assertSignals(rules, failed, "Failed rules")
        self.assertSignals(rules, unsuccessful, "Unsuccessful rules with signals")
        self.assertSignals(rules, no_signals, "Rules with no signals")
        self.assertSignals(rules, too_few_signals, "Rules with too few signals")
        self.assertSignals(rules, too_many_signals, "Rules with too many signals")
        #self.report_rules(rules, correct_signals, "Rules with the correct signals")

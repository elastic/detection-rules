# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test stack versioned schemas."""
import copy
import unittest
import uuid

import eql

from detection_rules.rule import TOMLRuleContents
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
        cls.v79_kql = dict(cls.v78_kql, author=["Elastic"], license="Elastic License v2")
        cls.v711_kql = copy.deepcopy(cls.v79_kql)
        # noinspection PyTypeChecker
        cls.v711_kql["threat"][0]["technique"][0]["subtechnique"] = [{
            "id": "T1059.001",
            "name": "PowerShell",
            "reference": "https://attack.mitre.org/techniques/T1059/001/"
        }]
        # noinspection PyTypeChecker
        cls.v711_kql["threat"].append({
            "framework": "MITRE ATT&CK",
            "tactic": {
                "id": "TA0008",
                "name": "Lateral Movement",
                "reference": "https://attack.mitre.org/tactics/TA0008/"
            },
        })

        cls.v79_threshold_contents = {
            "author": ["Elastic"],
            "description": "test description",
            "language": "kuery",
            "license": "Elastic License v2",
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
        }
        cls.v712_threshold_rule = dict(copy.deepcopy(cls.v79_threshold_contents), threshold={
            'field': ['destination.bytes', 'process.args'],
            'value': 75,
            'cardinality': {
                'field': 'user.name',
                'value': 2
            }
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
        api_contents = self.v79_kql
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
        api_contents = self.v712_threshold_rule
        self.assertDictEqual(downgrade(api_contents, CurrentSchema.STACK_VERSION), api_contents)
        self.assertDictEqual(downgrade(api_contents, CurrentSchema.STACK_VERSION + '.1'), api_contents)

        exc_msg = 'Cannot downgrade a threshold rule that has multiple threshold fields defined'
        with self.assertRaisesRegex(ValueError, exc_msg):
            downgrade(api_contents, '7.9')

        v712_threshold_contents_single_field = copy.deepcopy(api_contents)
        v712_threshold_contents_single_field['threshold']['field'].pop()

        with self.assertRaisesRegex(ValueError, "Cannot downgrade a threshold rule that has a defined cardinality"):
            downgrade(v712_threshold_contents_single_field, "7.9")

        v712_no_cardinality = copy.deepcopy(v712_threshold_contents_single_field)
        v712_no_cardinality['threshold'].pop('cardinality')
        self.assertEqual(downgrade(v712_no_cardinality, "7.9"), self.v79_threshold_contents)

        with self.assertRaises(ValueError):
            downgrade(v712_no_cardinality, "7.7")

        with self.assertRaisesRegex(ValueError, "Unsupported rule type"):
            downgrade(v712_no_cardinality, "7.8")

    def test_eql_validation(self):
        base_fields = {
            "author": ["Elastic"],
            "description": "test description",
            "index": ["filebeat-*"],
            "language": "eql",
            "license": "Elastic License v2",
            "name": "test rule",
            "risk_score": 21,
            "rule_id": str(uuid.uuid4()),
            "severity": "low",
            "type": "eql"
        }

        def build_rule(query):
            metadata = {"creation_date": "1970-01-01", "updated_date": "1970-01-01"}
            data = base_fields.copy()
            data["query"] = query
            obj = {"metadata": metadata, "rule": data}
            return TOMLRuleContents.from_dict(obj)

        build_rule("""
            process where process.name == "cmd.exe"
        """)

        with self.assertRaises(eql.EqlSyntaxError):
            build_rule("""
                    process where process.name == this!is$not#v@lid
            """)

        with self.assertRaises(eql.EqlSemanticError):
            build_rule("""
                    process where process.invalid_field == "hello world"
            """)

        with self.assertRaises(eql.EqlTypeMismatchError):
            build_rule("""
                    process where process.pid == "some string field"
            """)

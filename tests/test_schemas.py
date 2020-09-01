# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Test stack versioned schemas."""
import unittest
import uuid

from detection_rules.rule import Rule
from detection_rules.schemas import downgrade, CurrentSchema


class TestSchemas(unittest.TestCase):
    """Test schemas and downgrade functions."""

    @classmethod
    def setUpClass(cls):
        cls.compatible_rule = Rule("test.toml", {
            "author": ["Elastic"],
            "description": "test description",
            "index": ["filebeat-*"],
            "language": "kuery",
            "license": "Elastic License",
            "name": "test rule",
            "query": "process.name:test.query",
            "risk_score": 21,
            "rule_id": str(uuid.uuid4()),
            "severity": "low",
            "type": "query"
        })
        cls.versioned_rule = cls.compatible_rule.copy()
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
        api_contents = self.compatible_rule.contents
        self.assertDictEqual(downgrade(api_contents, CurrentSchema.STACK_VERSION), api_contents)
        self.assertDictEqual(downgrade(api_contents, "7.9"), api_contents)
        self.assertDictEqual(downgrade(api_contents, "7.9.2"), api_contents)
        self.assertDictEqual(downgrade(api_contents, "7.8"), {
            # "author": ["Elastic"],
            "description": "test description",
            "index": ["filebeat-*"],
            "language": "kuery",
            # "license": "Elastic License",
            "name": "test rule",
            "query": "process.name:test.query",
            "risk_score": 21,
            "rule_id": self.compatible_rule.id,
            "severity": "low",
            "type": "query"
        })

        with self.assertRaises(ValueError):
            downgrade(api_contents, "7.7")

    def test_versioned_downgrade(self):
        """Downgrade a KQL rule with version information"""
        api_contents = self.versioned_rule.contents
        self.assertDictEqual(downgrade(api_contents, CurrentSchema.STACK_VERSION), api_contents)
        self.assertDictEqual(downgrade(api_contents, "7.9"), api_contents)
        self.assertDictEqual(downgrade(api_contents, "7.9.2"), api_contents)
        self.assertDictEqual(downgrade(api_contents, "7.8"), {
            # "author": ["Elastic"],
            "description": "test description",
            "index": ["filebeat-*"],
            "language": "kuery",
            # "license": "Elastic License",
            "name": "test rule",
            "query": "process.name:test.query",
            "risk_score": 21,
            "rule_id": self.versioned_rule.id,
            "severity": "low",
            "type": "query",
            "version": 10,
        })

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

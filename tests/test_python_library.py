# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from detection_rules.rule_loader import RuleCollection

from .base import BaseRuleTest


class TestEQLInSet(BaseRuleTest):
    """Test EQL rule query in set override."""

    def test_eql_in_set(self):
        """Test that the query validation is working correctly."""
        rc = RuleCollection()
        eql_rule = {
            "metadata": {
                "creation_date": "2020/12/15",
                "integration": ["endpoint", "windows"],
                "maturity": "production",
                "min_stack_comments": "New fields added: required_fields, related_integrations, setup",
                "min_stack_version": "8.3.0",
                "updated_date": "2024/03/26",
            },
            "rule": {
                "author": ["Elastic"],
                "description": """
                Test Rule.
                """,
                "false_positives": ["Fake."],
                "from": "now-9m",
                "index": ["winlogbeat-*", "logs-endpoint.events.*", "logs-windows.sysmon_operational-*"],
                "language": "eql",
                "license": "Elastic License v2",
                "name": "Fake Test Rule",
                "references": [
                    "https://example.com",
                ],
                "risk_score": 47,
                "rule_id": "4fffae5d-8b7d-4e48-88b1-979ed42fd9a3",
                "severity": "medium",
                "tags": [
                    "Domain: Endpoint",
                    "OS: Windows",
                    "Use Case: Threat Detection",
                    "Tactic: Execution",
                    "Data Source: Elastic Defend",
                    "Data Source: Sysmon",
                ],
                "type": "eql",
                "query": """
                sequence by host.id, process.entity_id with maxspan = 5s
                [network where destination.ip in ("127.0.0.1", "::1")]
                """,
            },
        }
        expected_error_message = r"Error in both stack and integrations checks"
        with self.assertRaisesRegex(ValueError, expected_error_message):
            rc.load_dict(eql_rule)
        # Change to appropriate destination.address field
        eql_rule["rule"]["query"] = """
        sequence by host.id, process.entity_id with maxspan = 10s
        [network where destination.address in ("192.168.1.1", "::1")]
        """
        rc.load_dict(eql_rule)

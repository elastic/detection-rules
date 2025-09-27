# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test stack versioned schemas."""

import copy
import unittest
import uuid
from pathlib import Path

import eql
import pytest
import pytoml
from marshmallow import ValidationError
from semver import Version

from detection_rules import utils
from detection_rules.config import load_current_package_version
from detection_rules.esql_errors import EsqlSemanticError
from detection_rules.rule import TOMLRuleContents
from detection_rules.rule_loader import RuleCollection
from detection_rules.schemas import RULES_CONFIG, downgrade
from detection_rules.version_lock import VersionLockFile


class TestSchemas(unittest.TestCase):
    """Test schemas and downgrade functions."""

    @classmethod
    def setUpClass(cls):
        cls.current_version = load_current_package_version()

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
                        "reference": "https://attack.mitre.org/tactics/TA0001/",
                    },
                    "technique": [
                        {
                            "id": "T1059",
                            "name": "Command and Scripting Interpreter",
                            "reference": "https://attack.mitre.org/techniques/T1059/",
                        }
                    ],
                }
            ],
        }
        cls.v79_kql = dict(cls.v78_kql, author=["Elastic"], license="Elastic License v2")
        cls.v711_kql = copy.deepcopy(cls.v79_kql)
        # noinspection PyTypeChecker
        cls.v711_kql["threat"][0]["technique"][0]["subtechnique"] = [
            {"id": "T1059.001", "name": "PowerShell", "reference": "https://attack.mitre.org/techniques/T1059/001/"}
        ]
        # noinspection PyTypeChecker
        cls.v711_kql["threat"].append(
            {
                "framework": "MITRE ATT&CK",
                "tactic": {
                    "id": "TA0008",
                    "name": "Lateral Movement",
                    "reference": "https://attack.mitre.org/tactics/TA0008/",
                },
            }
        )

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
        cls.v712_threshold_rule = dict(
            copy.deepcopy(cls.v79_threshold_contents),
            threshold={
                "field": ["destination.bytes", "process.args"],
                "value": 75,
                "cardinality": [{"field": "user.name", "value": 2}],
            },
        )

    def test_query_downgrade_7_x(self):
        """Downgrade a standard KQL rule."""
        if Version.parse(self.current_version, optional_minor_and_patch=True).major > 7:
            return

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
            downgrade(self.v78_kql, "7.7", current_version="7.8")

    def test_versioned_downgrade_7_x(self):
        """Downgrade a KQL rule with version information"""
        if Version.parse(self.current_version, optional_minor_and_patch=True).major > 7:
            return

        api_contents = self.v79_kql
        self.assertDictEqual(downgrade(api_contents, "7.9"), api_contents)
        self.assertDictEqual(downgrade(api_contents, "7.9.2"), api_contents)

        api_contents78 = api_contents.copy()
        api_contents78.pop("author")
        api_contents78.pop("license")

        self.assertDictEqual(downgrade(api_contents, "7.8"), api_contents78)

        with self.assertRaises(ValueError):
            downgrade(api_contents, "7.7")

    def test_threshold_downgrade_7_x(self):
        """Downgrade a threshold rule that was first introduced in 7.9."""
        if Version.parse(self.current_version, optional_minor_and_patch=True).major > 7:
            return

        api_contents = self.v712_threshold_rule
        self.assertDictEqual(downgrade(api_contents, "7.13"), api_contents)
        self.assertDictEqual(downgrade(api_contents, "7.13.1"), api_contents)

        exc_msg = "Cannot downgrade a threshold rule that has multiple threshold fields defined"
        with self.assertRaisesRegex(ValueError, exc_msg):
            downgrade(api_contents, "7.9")

        v712_threshold_contents_single_field = copy.deepcopy(api_contents)
        v712_threshold_contents_single_field["threshold"]["field"].pop()

        with self.assertRaisesRegex(ValueError, "Cannot downgrade a threshold rule that has a defined cardinality"):
            downgrade(v712_threshold_contents_single_field, "7.9")

        v712_no_cardinality = copy.deepcopy(v712_threshold_contents_single_field)
        v712_no_cardinality["threshold"].pop("cardinality")
        self.assertEqual(downgrade(v712_no_cardinality, "7.9"), self.v79_threshold_contents)

        with self.assertRaises(ValueError):
            downgrade(v712_no_cardinality, "7.7")

        with self.assertRaisesRegex(ValueError, "Unsupported rule type"):
            downgrade(v712_no_cardinality, "7.8")

    def test_query_downgrade_8_x(self):
        """Downgrade a standard KQL rule."""
        if Version.parse(self.current_version, optional_minor_and_patch=True).major > 8:
            return

    def test_versioned_downgrade_8_x(self):
        """Downgrade a KQL rule with version information"""
        if Version.parse(self.current_version, optional_minor_and_patch=True).major > 8:
            return

    def test_threshold_downgrade_8_x(self):
        """Downgrade a threshold rule that was first introduced in 7.9."""
        if Version.parse(self.current_version, optional_minor_and_patch=True).major > 7:
            return

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
            "type": "eql",
        }

        def build_rule(query):
            metadata = {
                "creation_date": "1970/01/01",
                "updated_date": "1970/01/01",
                "min_stack_version": load_current_package_version(),
            }
            data = base_fields.copy()
            data["query"] = query
            obj = {"metadata": metadata, "rule": data}
            return TOMLRuleContents.from_dict(obj)

        build_rule("""
            process where process.name == "cmd.exe"
        """)

        example_text_fields = [
            "client.as.organization.name.text",
            "client.user.full_name.text",
            "client.user.name.text",
            "destination.as.organization.name.text",
            "destination.user.full_name.text",
            "destination.user.name.text",
            "error.message",
            "error.stack_trace.text",
            "file.path.text",
            "file.target_path.text",
            "host.os.full.text",
            "host.os.name.text",
            "host.user.full_name.text",
            "host.user.name.text",
        ]
        for text_field in example_text_fields:
            with self.assertRaises(eql.parser.EqlSchemaError):
                build_rule(f"""
                        any where {text_field} == "some string field"
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


class TestVersionLockSchema(unittest.TestCase):
    """Test that the version lock has proper entries."""

    @classmethod
    def setUpClass(cls):
        cls.version_lock_contents = {
            "33f306e8-417c-411b-965c-c2812d6d3f4d": {
                "rule_name": "Remote File Download via PowerShell",
                "sha256": "8679cd72bf85b67dde3dcfdaba749ed1fa6560bca5efd03ed41c76a500ce31d6",
                "type": "eql",
                "version": 4,
            },
            "34fde489-94b0-4500-a76f-b8a157cf9269": {
                "min_stack_version": "8.2",
                "previous": {
                    "7.13": {
                        "rule_name": "Telnet Port Activity",
                        "sha256": "3dd4a438c915920e6ddb0a5212603af5d94fb8a6b51a32f223d930d7e3becb89",
                        "type": "query",
                        "version": 9,
                    }
                },
                "rule_name": "Telnet Port Activity",
                "sha256": "b0bdfa73639226fb83eadc0303ad1801e0707743f96a36209aa58228d3bf6a89",
                "type": "query",
                "version": 10,
            },
        }

    def test_version_lock_no_previous(self):
        """Pass field validation on version lock without nested previous fields"""
        version_lock_contents = copy.deepcopy(self.version_lock_contents)
        VersionLockFile.from_dict({"data": version_lock_contents})

    @unittest.skipIf(RULES_CONFIG.bypass_version_lock, "Version lock bypassed")
    def test_version_lock_has_nested_previous(self):
        """Fail field validation on version lock with nested previous fields"""
        version_lock_contents = copy.deepcopy(self.version_lock_contents)
        with self.assertRaises(ValidationError):
            previous = version_lock_contents["34fde489-94b0-4500-a76f-b8a157cf9269"]["previous"]
            version_lock_contents["34fde489-94b0-4500-a76f-b8a157cf9269"]["previous"]["previous"] = previous
            VersionLockFile.from_dict({"data": version_lock_contents})


class TestVersions(unittest.TestCase):
    """Test that schema versioning aligns."""

    def test_stack_schema_map(self):
        """Test to ensure that an entry exists in the stack-schema-map for the current package version."""
        package_version = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
        stack_map = utils.load_etc_dump(["stack-schema-map.yaml"])
        err_msg = f"There is no entry defined for the current package ({package_version}) in the stack-schema-map"
        self.assertIn(package_version, [Version.parse(v) for v in stack_map], err_msg)


class TestESQLValidation(unittest.TestCase):
    """Test ESQL rule validation"""

    def test_esql_data_validation(self):
        """Test ESQL rule data validation"""

        # A random ESQL rule to deliver a test query
        rule_path = Path("tests/data/command_control_dummy_production_rule.toml")
        rule_body = rule_path.read_text()
        rule_dict = pytoml.loads(rule_body)

        # Most used order of the metadata fields
        query = """
            FROM logs-windows.powershell_operational* METADATA _id, _version, _index
            | WHERE event.code == "4104"
            | KEEP event.code
        """
        rule_dict["rule"]["query"] = query
        _ = RuleCollection().load_dict(rule_dict, path=rule_path)

        # The order of the metadata fields from the example in the docs -
        # https://www.elastic.co/guide/en/security/8.17/rules-ui-create.html#esql-non-agg-query
        query = """
            FROM logs-windows.powershell_operational* METADATA _id, _index, _version
            | WHERE event.code == "4104"
            | KEEP event.code
        """
        rule_dict["rule"]["query"] = query
        _ = RuleCollection().load_dict(rule_dict, path=rule_path)

        # Different metadata fields
        with pytest.raises(EsqlSemanticError):
            query = """
                FROM logs-windows.powershell_operational* METADATA _foo, _index
                | WHERE event.code == "4104"
                | KEEP event.code
            """
            rule_dict["rule"]["query"] = query
            _ = RuleCollection().load_dict(rule_dict, path=rule_path)

        # Missing `keep`
        with pytest.raises(EsqlSemanticError):
            query = """
                FROM logs-windows.powershell_operational* METADATA _id, _index, _version
                | WHERE event.code == "4104"
            """
            rule_dict["rule"]["query"] = query
            _ = RuleCollection().load_dict(rule_dict, path=rule_path)

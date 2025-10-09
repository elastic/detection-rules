# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import unittest
from copy import deepcopy

import pytest

from detection_rules.esql_errors import EsqlSchemaError, EsqlSyntaxError, EsqlTypeMismatchError
from detection_rules.misc import (
    get_default_config,
    getdefault,
)
from detection_rules.rule_loader import RuleCollection
from detection_rules.utils import get_path, load_rule_contents

from .base import BaseRuleTest

MAX_RETRIES = 3


@unittest.skipIf(get_default_config() is None, "Skipping remote validation due to missing config")
@unittest.skipIf(
    not getdefault("remote_esql_validation")(), "Skipping remote validation because remote_esql_validation is False"
)
class TestRemoteRules(BaseRuleTest):
    """Test rules against a remote Elastic stack instance."""

    def test_esql_related_integrations(self):
        """Test an ESQL rule has its related integrations built correctly."""
        file_path = get_path(["tests", "data", "command_control_dummy_production_rule.toml"])
        original_production_rule = load_rule_contents(file_path)
        production_rule = deepcopy(original_production_rule)[0]
        production_rule["metadata"]["integration"] = ["aws"]
        production_rule["rule"]["query"] = """
        from logs-aws.cloudtrail* metadata _id, _version, _index
        | where @timestamp > now() - 30 minutes
        and event.dataset in ("aws.cloudtrail", "aws.billing")
        and aws.cloudtrail.user_identity.arn is not null
        and aws.cloudtrail.user_identity.type == "IAMUser"
        | keep
        aws.cloudtrail.user_identity.type
        """
        rule = RuleCollection().load_dict(production_rule)
        related_integrations = rule.contents.to_api_format()["related_integrations"]
        for integration in related_integrations:
            assert integration["package"] == "aws", f"Expected 'aws', but got {integration['package']}"

    def test_esql_event_dataset_schema_error(self):
        """Test an ESQL rules that uses event.dataset field in the query validated the fields correctly."""
        # EsqlSchemaError
        file_path = get_path(["tests", "data", "command_control_dummy_production_rule.toml"])
        original_production_rule = load_rule_contents(file_path)
        # Test that a ValidationError is raised if the query doesn't match the schema
        production_rule = deepcopy(original_production_rule)[0]
        del production_rule["metadata"]["integration"]
        production_rule["rule"]["query"] = """
        from logs-aws.cloudtrail* metadata _id, _version, _index
        | where @timestamp > now() - 30 minutes
        and event.dataset in ("aws.billing")
        and aws.cloudtrail.user_identity.type == "IAMUser"
        | keep
        aws.cloudtrail.user_identity.type
        """
        with pytest.raises(EsqlSchemaError):
            _ = RuleCollection().load_dict(production_rule)

    def test_esql_type_mismatch_error(self):
        """Test an ESQL rules that uses event.dataset field in the query validated the fields correctly."""
        # EsqlSchemaError
        file_path = get_path(["tests", "data", "command_control_dummy_production_rule.toml"])
        original_production_rule = load_rule_contents(file_path)
        # Test that a ValidationError is raised if the query doesn't match the schema
        production_rule = deepcopy(original_production_rule)[0]
        production_rule["metadata"]["integration"] = ["aws"]
        production_rule["rule"]["query"] = """
        from logs-aws.cloudtrail* metadata _id, _version, _index
        | where @timestamp > now() - 30 minutes
        and event.dataset in ("aws.cloudtrail", "aws.billing")
        and aws.cloudtrail.user_identity.type == 5
        | keep
        aws.cloudtrail.user_identity.type
        """
        with pytest.raises(EsqlTypeMismatchError):
            _ = RuleCollection().load_dict(production_rule)

    def test_esql_syntax_error(self):
        """Test an ESQL rules that uses event.dataset field in the query validated the fields correctly."""
        # EsqlSchemaError
        file_path = get_path(["tests", "data", "command_control_dummy_production_rule.toml"])
        original_production_rule = load_rule_contents(file_path)
        # Test that a ValidationError is raised if the query doesn't match the schema
        production_rule = deepcopy(original_production_rule)[0]
        production_rule["metadata"]["integration"] = ["aws"]
        production_rule["rule"]["query"] = """
        from logs-aws.cloudtrail* metadata _id, _version, _index
        | where @timestamp > now() - 30 minutes
        and event.dataset in ("aws.cloudtrail", "aws.billing")
        and aws.cloudtrail.user_identity.type = "IAMUser"
        | keep
        aws.cloudtrail.user_identity.type
        """
        with pytest.raises(EsqlSyntaxError):
            _ = RuleCollection().load_dict(production_rule)

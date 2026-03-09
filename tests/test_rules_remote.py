# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import unittest
from copy import deepcopy

import pytest

from detection_rules.esql_errors import (
    EsqlSchemaError,
    EsqlSemanticError,
    EsqlSyntaxError,
    EsqlTypeMismatchError,
    EsqlUnknownIndexError,
)
from detection_rules.misc import (
    get_default_config,
    getdefault,
)
from detection_rules.rule_loader import RuleCollection
from detection_rules.utils import get_path, load_rule_contents

from .base import BaseRuleTest


@unittest.skipIf(get_default_config() is None, "Skipping remote validation due to missing config")
@unittest.skipIf(
    not getdefault("remote_esql_validation")(), "Skipping remote validation because remote_esql_validation is False"
)
class TestRemoteRules(BaseRuleTest):
    """Test rules against a remote Elastic stack instance."""

    def test_get_hashable_content_required_fields_popped_when_keep_star_used(self):
        """Hashable content must not contain required_fields when query uses keep * or field wildcards."""
        file_path = get_path(["tests", "data", "command_control_dummy_production_rule.toml"])
        original_production_rule = load_rule_contents(file_path)
        production_rule = deepcopy(original_production_rule)[0]
        # Non-aggregate queries must include _id, _version, _index in keep when keep is not exactly "*"
        base = "from logs-aws.cloudtrail* metadata _id, _version, _index\n"
        base += '| where event.action == "start"\n | eval Esql.entity_type = cloud.target.entity.type\n | keep '
        keep_star_queries = [
            base + "*",
            base + "Esql.*, _id, _version, _index",
            base + "host.name, Esql.*, _id, _version, _index",
            base + "event.*, _id, _version, _index",
        ]
        for query in keep_star_queries:
            production_rule_copy = deepcopy(production_rule)
            production_rule_copy["rule"]["query"] = query
            rule = RuleCollection().load_dict(production_rule_copy)
            hashable = rule.contents.get_hashable_content()
            assert "required_fields" not in hashable, f"required_fields should be popped for keep-star query: {query!r}"

    def test_get_hashable_content_required_fields_kept_when_no_keep_star(self):
        """Hashable content keeps required_fields when query uses explicit keep (no wildcards)."""
        file_path = get_path(["tests", "data", "command_control_dummy_production_rule.toml"])
        original_production_rule = load_rule_contents(file_path)
        production_rule = deepcopy(original_production_rule)[0]
        production_rule["rule"]["query"] = """
        from logs-aws.cloudtrail* metadata _id, _version, _index
        | where event.action == "start"
        | keep _id, _version, _index
        """
        rule = RuleCollection().load_dict(production_rule)
        api = rule.contents.to_api_format()
        hashable = rule.contents.get_hashable_content()
        if "required_fields" in api:
            assert "required_fields" in hashable, "required_fields must not be popped when keep has no wildcards"

    def test_get_hashable_content_required_fields_kept_for_explicit_keep_only(self):
        """Hashable content keeps required_fields when keep lists only explicit fields."""
        file_path = get_path(["tests", "data", "command_control_dummy_production_rule.toml"])
        original_production_rule = load_rule_contents(file_path)
        production_rule = deepcopy(original_production_rule)[0]
        production_rule["rule"]["query"] = """
        from logs-aws.cloudtrail* metadata _id, _version, _index
        | where event.action == "start"
        | keep host.name, user.name, _id, _version, _index
        """
        rule = RuleCollection().load_dict(production_rule)
        api = rule.contents.to_api_format()
        hashable = rule.contents.get_hashable_content()
        if "required_fields" in api:
            assert "required_fields" in hashable

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
        aws.cloudtrail.user_identity.type, _id, _version, _index
        """
        rule = RuleCollection().load_dict(production_rule)
        related_integrations = rule.contents.to_api_format()["related_integrations"]
        for integration in related_integrations:
            assert integration["package"] == "aws", f"Expected 'aws', but got {integration['package']}"

    def test_esql_non_dataset_package_related_integrations(self):
        """Test an ESQL rule has its related integrations built correctly with a non dataset package."""
        file_path = get_path(["tests", "data", "command_control_dummy_production_rule.toml"])
        original_production_rule = load_rule_contents(file_path)
        production_rule = deepcopy(original_production_rule)[0]
        production_rule["metadata"]["integration"] = ["aws_bedrock"]
        production_rule["rule"]["query"] = """
        from logs-aws_bedrock.invocation-* metadata _id, _version, _index
        // Filter for access denied errors from GenAI responses
        | where gen_ai.response.error_code == "AccessDeniedException"
        // keep ECS and response fields
        | keep
        user.id,
        gen_ai.request.model.id,
        cloud.account.id,
        gen_ai.response.error_code, _id, _version, _index
        """
        rule = RuleCollection().load_dict(production_rule)
        related_integrations = rule.contents.to_api_format()["related_integrations"]
        for integration in related_integrations:
            assert integration["package"] == "aws_bedrock", f"Expected 'aws_bedrock', but got {integration['package']}"

    def test_esql_event_dataset_schema_error(self):
        """Test an ESQL rule that uses event.dataset field in the query that restricts the schema failing validation."""
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
        aws.cloudtrail.user_identity.type, _id, _version, _index
        """
        with pytest.raises(EsqlSchemaError):
            _ = RuleCollection().load_dict(production_rule)

    def test_esql_type_mismatch_error(self):
        """Test an ESQL rule that produces a type error comparing a keyword to a number."""
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
        aws.cloudtrail.user_identity.type, _id, _version, _index
        """
        with pytest.raises(EsqlTypeMismatchError):
            _ = RuleCollection().load_dict(production_rule)

    def test_esql_syntax_error(self):
        """Test an ESQL rule that incorrectly using = for comparison."""
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
        aws.cloudtrail.user_identity.type, _id, _version, _index
        """
        with pytest.raises(EsqlSyntaxError):
            _ = RuleCollection().load_dict(production_rule)

    def test_esql_filtered_index(self):
        """Test an ESQL rule's schema validation to properly reduce it by the index and handle implicit fields."""
        file_path = get_path(["tests", "data", "command_control_dummy_production_rule.toml"])
        original_production_rule = load_rule_contents(file_path)
        # Test that a ValidationError is raised if the query doesn't match the schema
        production_rule = deepcopy(original_production_rule)[0]
        production_rule["metadata"]["integration"] = ["aws"]
        production_rule["rule"]["query"] = """
        from logs-aws.cloud* metadata _id, _version, _index
        | where @timestamp > now() - 30 minutes
        and aws.cloudtrail.user_identity.type == "IAMUser"
        | keep
        aws.*, _id, _version, _index
        """
        _ = RuleCollection().load_dict(production_rule)

    def test_esql_filtered_index_error(self):
        """Test an ESQL rule's schema validation when reduced by the index and check if the field is present."""
        file_path = get_path(["tests", "data", "command_control_dummy_production_rule.toml"])
        original_production_rule = load_rule_contents(file_path)
        # Test that a ValidationError is raised if the query doesn't match the schema
        production_rule = deepcopy(original_production_rule)[0]
        production_rule["metadata"]["integration"] = ["aws"]
        production_rule["rule"]["query"] = """
        from logs-aws.billing* metadata _id, _version, _index
        | where @timestamp > now() - 30 minutes
        and aws.cloudtrail.user_identity.type == "IAMUser"
        | keep
        aws.cloudtrail.user_identity.type, _id, _version, _index
        """
        with pytest.raises(EsqlSchemaError):
            _ = RuleCollection().load_dict(production_rule)

    def test_new_line_split_index(self):
        """Test an ESQL rule's index validation to ensure that it can handle new line split indices."""
        file_path = get_path(["tests", "data", "command_control_dummy_production_rule.toml"])
        original_production_rule = load_rule_contents(file_path)
        production_rule = deepcopy(original_production_rule)[0]
        production_rule["metadata"]["integration"] = ["aws"]
        production_rule["rule"]["query"] = """
        from logs-aws.cloud*, logs-network_traffic.http-*,
        logs-nginx.access-* metadata _id, _version, _index
        | where @timestamp > now() - 30 minutes
        and aws.cloudtrail.user_identity.type == "IAMUser"
        | keep
        aws.*, _id, _version, _index
        """
        _ = RuleCollection().load_dict(production_rule)

    def test_esql_endpoint_alerts_index(self):
        """Test an ESQL rule's schema validation using ecs fields in the alerts index."""
        file_path = get_path(["tests", "data", "command_control_dummy_production_rule.toml"])
        original_production_rule = load_rule_contents(file_path)
        production_rule = deepcopy(original_production_rule)[0]
        production_rule["rule"]["query"] = """
        from logs-endpoint.alerts-* METADATA _id, _version, _index
        | where event.code in ("malicious_file", "memory_signature", "shellcode_thread") and rule.name is not null
        | keep host.id, rule.name, event.code, _id, _version, _index
        | stats Esql.host_id_count_distinct = count_distinct(host.id) by rule.name, event.code
        | where Esql.host_id_count_distinct >= 3
        """
        _ = RuleCollection().load_dict(production_rule)

    def test_esql_endpoint_unknown_index(self):
        """Test an ESQL rule's index validation. This is expected to error on an unknown index."""
        file_path = get_path(["tests", "data", "command_control_dummy_production_rule.toml"])
        original_production_rule = load_rule_contents(file_path)
        production_rule = deepcopy(original_production_rule)[0]
        production_rule["rule"]["query"] = """
        from logs-endpoint.fake-*
        | where event.code in ("malicious_file", "memory_signature", "shellcode_thread") and rule.name is not null
        | keep host.id, rule.name, event.code, _id, _version, _index
        | stats Esql.host_id_count_distinct = count_distinct(host.id) by rule.name, event.code
        | where Esql.host_id_count_distinct >= 3
        """
        with pytest.raises(EsqlUnknownIndexError):
            _ = RuleCollection().load_dict(production_rule)

    def test_esql_endpoint_alerts_index_endpoint_fields(self):
        """Test an ESQL rule's schema validation using endpoint integration fields in the alerts index."""
        file_path = get_path(["tests", "data", "command_control_dummy_production_rule.toml"])
        original_production_rule = load_rule_contents(file_path)
        production_rule = deepcopy(original_production_rule)[0]
        production_rule["metadata"]["integration"] = []
        production_rule["rule"]["query"] = """
        from logs-endpoint.alerts-* METADATA _id, _version, _index
        | where event.code in ("malicious_file", "memory_signature", "shellcode_thread") and rule.name is not null and file.Ext.entry_modified > 0
        | keep host.id, rule.name, event.code, file.Ext.entry_modified, _id, _version, _index
        | stats Esql.host_id_count_distinct = count_distinct(host.id) by rule.name, event.code, file.Ext.entry_modified
        | where Esql.host_id_count_distinct >= 3
        """
        # This is a type mismatch error due to Elastic Container project including the Endpoint integration by default.
        # Otherwise one would expect an EsqlSchemaError due to the field not being present in the alerts index.
        with pytest.raises(EsqlTypeMismatchError):
            _ = RuleCollection().load_dict(production_rule)

    def test_esql_filtered_keep(self):
        """Test an ESQL rule's schema validation."""
        file_path = get_path(["tests", "data", "command_control_dummy_production_rule.toml"])
        original_production_rule = load_rule_contents(file_path)
        # Test that a ValidationError is raised if the query doesn't match the schema
        production_rule = deepcopy(original_production_rule)[0]
        production_rule["metadata"]["integration"] = ["aws"]
        production_rule["rule"]["query"] = """
        from logs-aws.billing* metadata _id, _version, _index
        | where @timestamp > now() - 30 minutes and aws.cloudtrail.user_identity.type == "IAMUser"
        | keep host.id, rule.name, event.code, _id, _version, _index
        | stats Esql.host_id_count_distinct = count_distinct(host.id) by rule.name, event.code
        | where Esql.host_id_count_distinct >= 3
        """
        with pytest.raises(EsqlSchemaError):
            _ = RuleCollection().load_dict(production_rule)

    def test_esql_non_ecs_schema_conflict_resolution(self):
        """Test an ESQL rule that has a known conflict between non_ecs and integrations for correct handling."""
        file_path = get_path(["tests", "data", "command_control_dummy_production_rule.toml"])
        original_production_rule = load_rule_contents(file_path)
        production_rule = deepcopy(original_production_rule)[0]
        production_rule["metadata"]["integration"] = ["azure", "o365"]
        production_rule["rule"]["query"] = """
        from logs-azure.signinlogs-* metadata _id, _version, _index
        | where @timestamp > now() - 30 minutes
        and event.dataset in ("azure.signinlogs")
        and event.outcome == "success"
        and azure.signinlogs.properties.user_id is not null
        | keep
        event.outcome, _id, _version, _index
        """
        _ = RuleCollection().load_dict(production_rule)

    def test_esql_multiple_keeps(self):
        """Test an ESQL rule that has multiple keeps in the query."""
        file_path = get_path(["tests", "data", "command_control_dummy_production_rule.toml"])
        original_production_rule = load_rule_contents(file_path)
        production_rule = deepcopy(original_production_rule)[0]
        production_rule["metadata"]["integration"] = ["aws"]
        production_rule["rule"]["query"] = """
        from logs-aws.cloudtrail* metadata _id, _version, _index
        | where @timestamp > now() - 30 minutes
        and event.dataset in ("aws.cloudtrail", "aws.billing")
        and aws.cloudtrail.user_identity.type == "IAMUser"
        | keep aws.cloudtrail.user_identity.type, _id, _version, _index
        | eval Esql.user_type = aws.cloudtrail.user_identity.type
        | keep Esql.user_type
        """
        with pytest.raises(EsqlSemanticError):
            _ = RuleCollection().load_dict(production_rule)

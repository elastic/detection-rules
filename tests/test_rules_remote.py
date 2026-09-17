# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import unittest
from copy import deepcopy
from types import SimpleNamespace

import pytest

from detection_rules.esql_errors import (
    EsqlSchemaError,
    EsqlSemanticError,
    EsqlSyntaxError,
    EsqlTypeMismatchError,
    EsqlUnknownIndexError,
)
from detection_rules.index_mappings import (
    align_flat_schema_to_flattened_fields,
    collect_flattened_fields,
    prepare_mappings,
)
from detection_rules.misc import (
    get_default_config,
    getdefault,
)
from detection_rules.rule import ESQLRuleData
from detection_rules.rule_loader import RuleCollection
from detection_rules.schemas.definitions import ESQL_DYNAMIC_FIELD_PREFIXES
from detection_rules.utils import get_path, load_rule_contents

from .base import BaseRuleTest


class TestESQLIndexMappings(unittest.TestCase):
    """Unit tests for the index mappings ES|QL validation prepares."""

    def test_collect_flattened_fields_keeps_first_source(self):
        """Known `flattened` fields are collected with the name of the first mapping that declares them."""
        mappings: dict[str, dict[str, object]] = {
            "existing-index-template-mappings": {"custom_ns": {"properties": {"payload": {"type": "flattened"}}}},
            "azure-platformlogs": {
                "azure": {"properties": {"platformlogs": {"properties": {"properties": {"type": "flattened"}}}}}
            },
            "other-integration": {"custom_ns": {"properties": {"payload": {"type": "flattened"}}}},
        }
        self.assertEqual(
            collect_flattened_fields(mappings),
            {
                "custom_ns.payload": "existing-index-template-mappings",
                "azure.platformlogs.properties": "azure-platformlogs",
            },
        )

    def test_flat_schema_subfields_collapsed_onto_flattened_parent(self):
        """Entries below a known `flattened` field collapse onto that field instead of nesting as `object`."""
        flattened_fields = {"azure.platformlogs.properties": "azure-platformlogs"}
        flat_schema = {
            "azure.platformlogs.properties.log.verb": "keyword",
            "azure.platformlogs.properties.id": "keyword",
            "azure.platformlogs.category": "keyword",
            "user.name": "keyword",
        }
        logged: list[str] = []

        aligned = align_flat_schema_to_flattened_fields(
            flat_schema, flattened_fields, "rule-non-ecs-index", logged.append
        )

        self.assertEqual(
            aligned,
            {
                "azure.platformlogs.properties": "flattened",
                "azure.platformlogs.category": "keyword",
                "user.name": "keyword",
            },
        )
        self.assertEqual(len(logged), 1)
        self.assertIn("`azure.platformlogs.properties`", logged[0])
        self.assertIn("`flattened` in `azure-platformlogs`", logged[0])
        self.assertIn("`object` in `rule-non-ecs-index`", logged[0])

    def test_flat_schema_scalar_conflict_collapsed_onto_flattened_field(self):
        """An entry typed differently from a known `flattened` field is retyped as `flattened`."""
        flattened_fields = {"azure.platformlogs.properties": "azure-platformlogs"}
        flat_schema = {
            "azure.platformlogs.properties": "keyword",
            "azure.platformlogs.properties.log.verb": "keyword",
        }
        logged: list[str] = []

        aligned = align_flat_schema_to_flattened_fields(
            flat_schema, flattened_fields, "custom logs-azure.platformlogs-*", logged.append
        )

        self.assertEqual(aligned, {"azure.platformlogs.properties": "flattened"})
        self.assertEqual(len(logged), 1)
        self.assertIn("`keyword` in `custom logs-azure.platformlogs-*`", logged[0])

    def test_flat_schema_unchanged_without_conflicts(self):
        """Schemas that already agree with the known `flattened` fields, or have none, are left as they are."""
        flat_schema = {"azure.platformlogs.properties": "flattened", "user.name": "keyword"}
        logged: list[str] = []

        self.assertEqual(align_flat_schema_to_flattened_fields(flat_schema, {}, "x", logged.append), flat_schema)
        self.assertEqual(
            align_flat_schema_to_flattened_fields(
                flat_schema, {"azure.platformlogs.properties": "azure-platformlogs"}, "x", logged.append
            ),
            flat_schema,
        )
        self.assertEqual(logged, [])

    def test_prepare_mappings_aligns_schema_mappings_with_flattened_fields(self):
        """`prepare_mappings` collapses non-ecs and custom subfields onto `flattened` fields from both real sources.

        This pins the ordering inside `prepare_mappings`: the integration and existing index template mappings
        must be loaded before the schema-derived mappings are converted, otherwise the known `flattened` fields
        are empty at conversion time and the ambiguous mapping error from #6724 silently returns.
        """
        index = "logs-azure.platformlogs-*"
        # `flattened` in the existing index template mappings only
        existing_mappings: dict[str, object] = {"custom_ns": {"properties": {"payload": {"type": "flattened"}}}}
        # `flattened` in the integration mappings only
        integration_mapping: dict[str, object] = {
            "azure": {"properties": {"platformlogs": {"properties": {"properties": {"type": "flattened"}}}}}
        }
        non_ecs_schema = {index: {"azure": {"platformlogs": {"properties": {"log": {"verb": "keyword"}}}}}}
        custom_schema = {index: {"custom_ns": {"payload": {"key": "keyword"}}}}
        logged: list[str] = []

        with (
            unittest.mock.patch(
                "detection_rules.index_mappings.get_existing_mappings",
                return_value=(existing_mappings, {index: deepcopy(existing_mappings)}),
            ),
            unittest.mock.patch("detection_rules.index_mappings.get_rule_integrations", return_value=["azure"]),
            unittest.mock.patch("detection_rules.index_mappings.load_integrations_manifests", return_value={}),
            unittest.mock.patch("detection_rules.index_mappings.load_integrations_schemas", return_value={}),
            unittest.mock.patch(
                "detection_rules.index_mappings.prepare_integration_mappings",
                return_value=(deepcopy(integration_mapping), {"azure-platformlogs": integration_mapping}),
            ),
            unittest.mock.patch("detection_rules.ecs.get_non_ecs_schema", return_value=non_ecs_schema),
            unittest.mock.patch("detection_rules.ecs.get_custom_schemas", return_value=custom_schema),
        ):
            _, index_lookup, combined_mappings = prepare_mappings(
                elastic_client=object(),  # type: ignore[reportArgumentType]
                indices=[index],
                event_dataset_integrations=[],
                metadata=SimpleNamespace(),  # type: ignore[reportArgumentType]
                stack_version="9.3.0",
                log=logged.append,
            )

        # non-ecs subfields collapsed onto the integration's `flattened` field
        self.assertEqual(
            index_lookup["rule-non-ecs-index"]["azure"]["properties"]["platformlogs"]["properties"]["properties"],
            {"type": "flattened"},
        )
        # custom subfields collapsed onto the existing index template's `flattened` field
        self.assertEqual(combined_mappings["custom_ns"]["properties"]["payload"], {"type": "flattened"})
        warnings = [line for line in logged if "Mapping it as `flattened`" in line]
        self.assertEqual(len(warnings), 3)
        self.assertTrue(any("`azure.platformlogs.properties`" in w and "`non-ecs logs-azure" in w for w in warnings))
        self.assertTrue(any("`azure.platformlogs.properties`" in w and "`rule-non-ecs-index`" in w for w in warnings))
        self.assertTrue(any("`custom_ns.payload`" in w and "`existing-index-template-mappings`" in w for w in warnings))


@unittest.skipIf(get_default_config() is None, "Skipping remote validation due to missing config")
@unittest.skipIf(not getdefault("esql_validation")(), "Skipping ES|QL validation because esql_validation is False")
class TestRemoteRules(BaseRuleTest):
    """Test rules against a remote Elastic stack instance."""

    def test_get_hashable_content_required_fields_popped_when_keep_star_used(self):
        """Hashable content must not contain required_fields when query uses keep * or field wildcards."""
        file_path = get_path(["tests", "data", "command_control_dummy_production_rule.toml"])
        original_production_rule = load_rule_contents(file_path)
        production_rule = deepcopy(original_production_rule)[0]
        # Non-aggregate queries must include _id, _version, _index in keep when keep is not exactly "*"
        base = "from logs-aws.cloudtrail* metadata _id, _version, _index\n"
        base += '| where event.action == "start"\n | eval Esql.entity_type = cloud.target.machine.type\n | keep '
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
        and data_stream.dataset in ("aws.cloudtrail", "aws.billing")
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
        and data_stream.dataset in ("aws.cloudtrail", "aws.billing")
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

    def test_esql_required_fields_omit_engine_columns(self):
        """ESQL required_fields must not list Esql.* / Esql_priv.* (not index mappings)."""
        for rule in self.all_rules:
            data = rule.contents.data
            if not isinstance(data, ESQLRuleData):
                continue
            index = data.get("index") or []
            for rf in data.get_required_fields(index) or []:
                name = rf["name"]
                assert not name.startswith(ESQL_DYNAMIC_FIELD_PREFIXES), (
                    f"{rule.id} - {rule.name}: required_fields must not include ES|QL engine columns "
                    f"(not index mappings): {name!r}"
                )

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
        # Remote validation used to raise EsqlTypeMismatchError only because the Elastic
        # Container test stack shipped the Endpoint integration by default. Local schemas do
        # not map file.Ext.entry_modified on logs-endpoint.alerts-* (no integration is set),
        # and the field is referenced as a STATS grouping, which the offline analyzer treats
        # as pipeline-defined — so the rule loads. Unmapped fields referenced outside a
        # grouping still raise EsqlSchemaError (see test_esql_filtered_keep).
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

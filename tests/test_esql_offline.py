# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Offline ES|QL validation unit tests (no remote cluster)."""

from __future__ import annotations

import re
from copy import deepcopy

import pytest

from detection_rules.esql import (
    collect_index_field_schemas,
    infer_packages_from_indices,
    normalize_dataset_package,
)
from detection_rules.esql_errors import EsqlSchemaError, EsqlUnknownIndexError
from detection_rules.index_mappings import combine_index_mappings, prune_scalar_fields_with_subfields
from detection_rules.rule_loader import RuleCollection
from detection_rules.utils import get_path, load_rule_contents


def _sample_rule() -> dict:
    file_path = get_path(["tests", "data", "command_control_dummy_production_rule.toml"])
    return deepcopy(load_rule_contents(file_path)[0])


class TestEsqlOfflineSchemaFailures:
    """Queries that must fail offline validation with allow_missing=False."""

    def test_unknown_index_raises_offline(self) -> None:
        """Parity with remote test_esql_endpoint_unknown_index."""
        rule = _sample_rule()
        rule["metadata"]["integration"] = ["endpoint"]
        rule["rule"]["query"] = """
        FROM logs-endpoint.fake-* METADATA _id, _version, _index
        | WHERE event.code in ("malicious_file", "memory_signature", "shellcode_thread")
        | KEEP host.id, rule.name, event.code, _id, _version, _index
        """
        with pytest.raises(EsqlUnknownIndexError, match=re.escape("logs-endpoint.fake")):
            RuleCollection().load_dict(rule)

    def test_unknown_field_raises_schema_error(self) -> None:
        rule = _sample_rule()
        rule["metadata"]["integration"] = ["endpoint"]
        rule["rule"]["query"] = """
        FROM logs-endpoint.events.process-* METADATA _id, _version, _index
        | WHERE totally.made_up.field == "x"
        | KEEP totally.made_up.field, _id, _version, _index
        """
        with pytest.raises(EsqlSchemaError, match=re.escape("totally.made_up.field")):
            RuleCollection().load_dict(rule)

    def test_keep_only_unknown_field_raises_schema_error(self) -> None:
        rule = _sample_rule()
        rule["metadata"]["integration"] = ["endpoint"]
        rule["rule"]["query"] = """
        FROM logs-endpoint.events.process-* METADATA _id, _version, _index
        | KEEP totally_unknown_keep_field, _id, _version, _index
        """
        with pytest.raises(EsqlSchemaError, match="totally_unknown_keep_field"):
            RuleCollection().load_dict(rule)

    def test_field_from_unrelated_package_raises_schema_error(self) -> None:
        """Endpoint-only package plan must reject azure-only fields."""
        rule = _sample_rule()
        rule["metadata"]["integration"] = ["endpoint"]
        rule["rule"]["query"] = """
        FROM logs-endpoint.events.process-* METADATA _id, _version, _index
        | WHERE azure.signinlogs.properties.session_id == "abc"
        | KEEP azure.signinlogs.properties.session_id, _id, _version, _index
        """
        with pytest.raises(EsqlSchemaError, match=re.escape("azure.signinlogs.properties.session_id")):
            RuleCollection().load_dict(rule)

    def test_field_outside_index_stream_raises_schema_error(self) -> None:
        """billing index must not validate cloudtrail-only fields (stream filter)."""
        rule = _sample_rule()
        rule["metadata"]["integration"] = ["aws"]
        rule["rule"]["query"] = """
        FROM logs-aws.billing-* METADATA _id, _version, _index
        | WHERE aws.cloudtrail.user_identity.type == "IAMUser"
        | KEEP aws.cloudtrail.user_identity.type, _id, _version, _index
        """
        with pytest.raises(EsqlSchemaError):
            RuleCollection().load_dict(rule)


class TestEsqlOfflineSchemaPasses:
    """Queries that must pass once schemas / defined columns are correct."""

    def test_alert_index_kibana_alert_fields_pass(self) -> None:
        rule = _sample_rule()
        del rule["metadata"]["integration"]
        rule["rule"]["query"] = """
        FROM .alerts-security.* METADATA _id, _version, _index
        | WHERE kibana.alert.rule.name IS NOT NULL AND kibana.alert.risk_score > 21
        | KEEP kibana.alert.rule.name, kibana.alert.risk_score, _id, _version, _index
        """
        loaded = RuleCollection().load_dict(rule)
        assert loaded.contents.data.language == "esql"

    def test_grok_named_capture_field_passes(self) -> None:
        rule = _sample_rule()
        rule["metadata"]["integration"] = ["aws"]
        rule["rule"]["query"] = """
        FROM logs-aws.cloudtrail-* METADATA _id, _version, _index
        | WHERE event.dataset == "aws.cloudtrail"
        | GROK aws.cloudtrail.request_parameters "[Cc]ontent=(?<script_b64>[A-Za-z0-9+/=]+)"
        | WHERE script_b64 IS NOT NULL
        | KEEP script_b64, _id, _version, _index
        """
        loaded = RuleCollection().load_dict(rule)
        assert "script_b64" in loaded.contents.data.query


class TestEsqlSchemaHelpers:
    def test_googlecloud_aliases_to_gcp(self) -> None:
        assert normalize_dataset_package("googlecloud") == "gcp"
        assert normalize_dataset_package("gcp") == "gcp"

    def test_infer_packages_from_indices(self) -> None:
        packages = infer_packages_from_indices(
            ["logs-aws.cloudtrail-*", "metrics-*", ".alerts-security.*", "logs-googlecloud.audit-*"]
        )
        assert "aws" in packages
        assert "system" in packages
        assert "gcp" in packages
        assert ".alerts-security.*" not in packages

    def test_collect_index_field_schemas_includes_alert_fields(self) -> None:
        fields = collect_index_field_schemas([".alerts-security.*"])
        assert fields.get("kibana.alert.rule.name") == "keyword"
        assert fields.get("kibana.alert.risk_score") == "long"

    def test_combine_index_mappings_prefers_object_over_scalar(self) -> None:
        dest = {"model": {"type": "keyword"}}
        src = {"model": {"properties": {"id": {"type": "keyword"}}}}
        combine_index_mappings(dest, src)
        assert "properties" in dest["model"]
        assert dest["model"]["properties"]["id"]["type"] == "keyword"

    def test_prune_scalar_fields_with_subfields(self) -> None:
        mapping = {"data": {"type": "keyword", "properties": {"nested": {"type": "keyword"}}}}
        pruned = prune_scalar_fields_with_subfields(mapping)
        assert pruned["data"]["type"] == "keyword"
        assert "properties" not in pruned["data"]

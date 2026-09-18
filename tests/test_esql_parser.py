# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""ES|QL parser validation unit tests (no remote cluster)."""

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

    def test_keyword_compared_to_number_raises_type_mismatch(self) -> None:
        """Parity with remote test_esql_type_mismatch_error (keyword == number)."""
        from detection_rules.esql_errors import EsqlTypeMismatchError

        rule = _sample_rule()
        rule["metadata"]["integration"] = ["aws"]
        rule["rule"]["query"] = """
        FROM logs-aws.cloudtrail-* METADATA _id, _version, _index
        | WHERE aws.cloudtrail.user_identity.type == 5
        | KEEP aws.cloudtrail.user_identity.type, _id, _version, _index
        """
        with pytest.raises(EsqlTypeMismatchError):
            RuleCollection().load_dict(rule)

    def test_long_field_like_string_raises_type_mismatch(self) -> None:
        from detection_rules.esql_errors import EsqlTypeMismatchError

        rule = _sample_rule()
        rule["metadata"]["integration"] = ["endpoint"]
        rule["rule"]["query"] = """
        FROM logs-endpoint.events.process-* METADATA _id, _version, _index
        | WHERE process.pid LIKE "1*"
        | KEEP process.pid, _id, _version, _index
        """
        with pytest.raises(EsqlTypeMismatchError):
            RuleCollection().load_dict(rule)

    def test_long_ordered_against_string_raises_type_mismatch(self) -> None:
        from detection_rules.esql_errors import EsqlTypeMismatchError

        rule = _sample_rule()
        rule["metadata"]["integration"] = ["endpoint"]
        rule["rule"]["query"] = """
        FROM logs-endpoint.events.process-* METADATA _id, _version, _index
        | WHERE process.pid > "10"
        | KEEP process.pid, _id, _version, _index
        """
        with pytest.raises(EsqlTypeMismatchError):
            RuleCollection().load_dict(rule)


class TestEsqlOfflineSchemaPasses:
    """Queries that must pass once schemas / defined columns are correct."""

    def test_nested_kql_uppercase_operators_pass(self) -> None:
        """Nested KQL() must accept uppercase NOT/AND/OR (Kibana parity)."""
        rule = _sample_rule()
        del rule["metadata"]["integration"]
        rule["rule"]["query"] = '''
        FROM .alerts-security.* METADATA _id, _version, _index
        | WHERE KQL("""NOT kibana.alert.rule.name : never-match-token""")
        | KEEP kibana.alert.rule.name, _id, _version, _index
        '''
        loaded = RuleCollection().load_dict(rule)
        assert loaded.contents.data.language == "esql"

    def test_nested_kql_unknown_field_raises_schema_error(self) -> None:
        """Nested KQL() payloads must schema-validate against the ValidationTarget."""
        rule = _sample_rule()
        rule["metadata"]["integration"] = ["endpoint"]
        rule["rule"]["query"] = '''
        FROM logs-endpoint.events.process-* METADATA _id, _version, _index
        | WHERE KQL("""totally.made_up.nested_kql_field : x""")
        | KEEP host.name, _id, _version, _index
        '''
        with pytest.raises(
            (EsqlSchemaError, Exception),
            match=r"totally\.made_up\.nested_kql_field|Unknown field|Field",
        ):
            RuleCollection().load_dict(rule)

    def test_eql_parse_hook_wired(self) -> None:
        """eql_parse hook is installed for when ES|QL grammar supports EQL()."""
        from detection_rules.rule import set_esql_config

        cfg = set_esql_config("9.5.0")
        assert callable(cfg.context.get("kql_parse"))
        assert callable(cfg.context.get("eql_parse"))
        # Hook accepts a simple event query (prep; grammar may not yet emit NestedQuery).
        tree = cfg.context["eql_parse"]('process where process.name == "cmd.exe"')
        assert tree is not None

    def test_set_esql_config_features_map_gates_kql(self) -> None:
        """set_esql_config must put a features dict that verify_features honors."""
        import esql

        from detection_rules.rule import set_esql_config

        cfg = set_esql_config("8.14.0")
        flags = cfg.context.get("features")
        assert isinstance(flags, dict)
        assert flags.get("kql_function") is False

        with cfg, esql.Schema({}, allow_missing=True), pytest.raises(esql.EsqlVersionError, match=r"KQL\(\)"):
            esql.parse_query('FROM logs-* | WHERE KQL("a:b") | KEEP _id')

        cfg_ok = set_esql_config("8.15.0")
        assert cfg_ok.context["features"]["kql_function"] is True
        with cfg_ok, esql.Schema({}, allow_missing=True):
            esql.parse_query('FROM logs-* | WHERE KQL("a:b") | KEEP _id')

    def test_completion_query_requires_9_3_grammar(self) -> None:
        """Modern COMPLETION … WITH { } must fail on 8.19 and pass from 9.3."""
        import esql

        from detection_rules.rule import set_esql_config

        query = """
        FROM .alerts-security.* METADATA _id, _version, _index
        | COMPLETION triage_result = "x" WITH { "inference_id": ".anthropic-claude-4.6-sonnet-completion"}
        | KEEP triage_result, _id, _version, _index
        """
        with set_esql_config("8.19.0"), esql.Schema({}, allow_missing=True), pytest.raises(esql.EsqlSyntaxError):
            esql.parse_query(query)
        with set_esql_config("9.3.0"), esql.Schema({}, allow_missing=True):
            tree = esql.parse_query(query)
        assert any(isinstance(c, esql.ast.CompletionCommand) for c in tree.commands)

    def test_ast_reuse_across_same_grammar_targets(self) -> None:
        """validate() must reuse self.ast for the current-package grammar key."""
        from detection_rules.rule_validators import ESQLValidator

        rule = _sample_rule()
        rule["metadata"]["integration"] = ["endpoint"]
        rule["rule"]["query"] = """
        FROM logs-endpoint.events.process-* METADATA _id, _version, _index
        | WHERE process.name == "cmd.exe"
        | KEEP process.name, _id, _version, _index
        """
        loaded = RuleCollection().load_dict(rule)
        validator = ESQLValidator(loaded.contents.data.query)
        first = id(validator.ast)
        validator.validate(loaded.contents.data, loaded.contents.metadata, force_remote_validation=False)
        # Same grammar → same tree object still referenced after validate
        assert id(validator.ast) == first

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


class TestEsqlCorpusOffline:
    """Re-validate every production ES|QL rule offline (remote replacement path)."""

    def test_all_production_esql_rules_validate_offline(self) -> None:
        from detection_rules.rule_validators import ESQLValidator

        collection = RuleCollection.default()
        esql_rules = [r for r in collection.rules if getattr(r.contents.data, "language", None) == "esql"]
        assert len(esql_rules) >= 200, f"expected a full ES|QL corpus, got {len(esql_rules)}"

        failures: list[str] = []
        for rule in esql_rules:
            data = rule.contents.data
            meta = rule.contents.metadata
            name = str(getattr(rule, "path", None) or data.rule_id)
            try:
                ESQLValidator(data.query).validate(data, meta, force_remote_validation=False)
            except Exception as exc:  # noqa: BLE001 — collect all failures
                failures.append(f"{name}: {type(exc).__name__}: {exc}")

        assert not failures, "Offline ES|QL validation failures:\n" + "\n".join(failures[:40])


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
        assert fields.get("kibana.alert.building_block_type") == "keyword"
        assert fields.get("kibana.alert.rule.tags") == "keyword"

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

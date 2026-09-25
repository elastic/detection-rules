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
    collect_lookup_index_field_schemas,
    get_esql_lookup_join_targets,
    infer_packages_from_indices,
    lookup_index_uses_ecs,
    normalize_dataset_package,
)
from detection_rules.esql_errors import EsqlSchemaError, EsqlUnknownIndexError
from detection_rules.index_mappings import assert_known_esql_indices, collect_known_esql_index_patterns
from detection_rules.rule import get_unique_query_fields
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

    def test_stream_keys_cover_metrics_and_traces(self) -> None:
        """Fleet streams are known as logs, metrics, and traces index patterns."""
        patterns = collect_known_esql_index_patterns({"system-cpu"}, [])
        assert "logs-system.cpu*" in patterns
        assert "metrics-system.cpu*" in patterns
        assert "traces-system.cpu*" in patterns
        assert assert_known_esql_indices(["metrics-system.cpu-*"], {"system-cpu"})
        assert assert_known_esql_indices(["packetbeat-*"], set())

    def test_one_unknown_index_among_known_still_raises(self) -> None:
        """Every FROM index must match a known pattern."""
        rule = _sample_rule()
        rule["metadata"]["integration"] = ["endpoint"]
        rule["rule"]["query"] = """
        FROM logs-endpoint.events.process-*, logs-endpoint.fake-* METADATA _id, _version, _index
        | WHERE host.name == "workstation"
        | KEEP host.name, _id, _version, _index
        """
        with pytest.raises(EsqlUnknownIndexError, match=re.escape("logs-endpoint.fake")):
            RuleCollection().load_dict(rule)

    def test_unknown_dataset_package_does_not_raise_manifest_error(self) -> None:
        """A data_stream.dataset value outside the manifests must not raise ValueError."""
        rule = _sample_rule()
        rule["metadata"]["integration"] = ["endpoint"]
        rule["rule"]["query"] = """
        FROM logs-endpoint.events.process-* METADATA _id, _version, _index
        | WHERE data_stream.dataset == "notapkg.stream"
        | KEEP host.name, _id, _version, _index
        """
        loaded = RuleCollection().load_dict(rule)
        assert loaded.contents.data.language == "esql"

    def test_custom_rules_dir_skips_unknown_index(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Custom and customized prebuilt rules may use data streams outside Fleet manifests."""
        monkeypatch.setattr("detection_rules.index_mappings.CUSTOM_RULES_DIR", "custom-rules-dir")
        rule = _sample_rule()
        rule["metadata"]["integration"] = []
        rule["rule"]["query"] = """
        FROM logs-acme.private-* METADATA _id, _version, _index
        | WHERE host.name == "workstation"
        | KEEP host.name, _id, _version, _index
        """
        loaded = RuleCollection().load_dict(rule)
        assert loaded.contents.data.language == "esql"

    def test_older_grammar_reparse_uses_detection_rules_syntax_error(self) -> None:
        """A reparse for an older stack grammar raises detection_rules EsqlSyntaxError."""
        import esql

        from detection_rules.esql_errors import EsqlSyntaxError

        rule = _sample_rule()
        rule["metadata"]["min_stack_version"] = "8.19.0"
        rule["metadata"]["integration"] = ["endpoint"]
        # Map-form COMPLETION parses on 9.3+ grammars and is rejected by the 8.19 grammar.
        rule["rule"]["query"] = """
        FROM logs-endpoint.events.process-* METADATA _id, _version, _index
        | COMPLETION triage_result = "x" WITH { "inference_id": "model" }
        | KEEP triage_result, _id, _version, _index
        """
        with pytest.raises(EsqlSyntaxError, match=r"COMPLETION|mismatched") as caught:
            RuleCollection().load_dict(rule)
        assert not isinstance(caught.value, esql.EsqlSyntaxError)

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

    def test_combined_from_unions_sibling_stream_fields(self) -> None:
        """One FROM of several indices still sees fields from any of those indices."""
        rule = _sample_rule()
        rule["metadata"]["integration"] = ["aws"]
        rule["rule"]["query"] = """
        FROM logs-aws.cloudtrail-*, logs-aws.billing-* METADATA _id, _version, _index
        | WHERE aws.cloudtrail.user_identity.type == "IAMUser"
        | KEEP aws.cloudtrail.user_identity.type, _id, _version, _index
        """
        loaded = RuleCollection().load_dict(rule)
        assert loaded.contents.data.language == "esql"

    def test_subquery_does_not_see_sibling_stream_fields(self) -> None:
        """A field present on one subquery source is unknown inside the other."""
        rule = _sample_rule()
        rule["metadata"]["integration"] = ["aws"]
        rule["rule"]["query"] = """
        FROM
          (FROM logs-aws.cloudtrail-* | KEEP aws.cloudtrail.user_identity.type),
          (FROM logs-aws.billing-* | WHERE aws.cloudtrail.user_identity.type == "IAMUser" | KEEP host.name)
        | STATS count = COUNT(*) BY host.name
        | KEEP count, host.name
        """
        with pytest.raises(EsqlSchemaError, match=re.escape("aws.cloudtrail.user_identity.type")):
            RuleCollection().load_dict(rule)

    def test_unique_fields_include_nested_kql(self) -> None:
        """Rule search and packaging see fields that appear only inside KQL()."""
        rule = _sample_rule()
        rule["metadata"]["integration"] = ["endpoint"]
        rule["metadata"]["min_stack_version"] = "8.16.0"
        rule["rule"]["query"] = """
        FROM logs-endpoint.events.process-* METADATA _id, _version, _index
        | WHERE KQL("process.command_line: *whoami*")
        | KEEP host.name, _id, _version, _index
        """
        loaded = RuleCollection().load_dict(rule)
        fields = get_unique_query_fields(loaded)
        assert fields is not None
        assert "process.command_line" in fields

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
        with pytest.raises(EsqlSchemaError, match="Unknown field"):
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
        validator.validate(loaded.contents.data, loaded.contents.metadata)
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
                ESQLValidator(data.query).validate(data, meta)
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


class TestEsqlLookupJoin:
    """LOOKUP JOIN schemas are passed via Schema(lookups=), not dumped into FROM."""

    def test_extract_lookup_targets(self) -> None:
        query = """
        FROM logs-endpoint.events.process-* METADATA _id, _version, _index
        | LOOKUP JOIN logs-aws.cloudtrail-* ON host.name
        | KEEP host.name, _id, _version, _index
        """
        assert get_esql_lookup_join_targets(query) == ["logs-aws.cloudtrail-*"]

    def test_lookup_index_uses_ecs_for_datastreams_not_named_tables(self) -> None:
        assert lookup_index_uses_ecs("logs-aws.cloudtrail-*") is True
        assert lookup_index_uses_ecs("threat_list") is False

    def test_collect_lookup_index_field_schemas_does_not_dump_endpoint(self) -> None:
        fields = collect_lookup_index_field_schemas(["logs-aws.cloudtrail-*"])
        aws_fields = fields["logs-aws.cloudtrail-*"]
        assert "aws.cloudtrail.flattened.request_parameters.key" in aws_fields
        assert "process.Ext.api.name" not in aws_fields

    def test_unknown_lookup_index_raises_offline(self) -> None:
        rule = _sample_rule()
        rule["metadata"]["integration"] = ["endpoint"]
        rule["metadata"]["min_stack_version"] = "8.16.0"
        rule["rule"]["query"] = """
        FROM logs-endpoint.events.process-* METADATA _id, _version, _index
        | LOOKUP JOIN totally-unknown-lookup-index ON host.name
        | KEEP host.name, _id, _version, _index
        """
        with pytest.raises(EsqlUnknownIndexError, match="totally-unknown-lookup-index"):
            RuleCollection().load_dict(rule)

    def test_lookup_join_fields_available_after_join(self) -> None:
        rule = _sample_rule()
        rule["metadata"]["integration"] = ["endpoint"]
        rule["metadata"]["min_stack_version"] = "8.16.0"
        rule["rule"]["query"] = """
        FROM logs-endpoint.events.process-* METADATA _id, _version, _index
        | LOOKUP JOIN logs-aws.cloudtrail-* ON host.name
        | KEEP host.name, aws.cloudtrail.user_identity.type, _id, _version, _index
        """
        loaded = RuleCollection().load_dict(rule)
        assert loaded.contents.data.language == "esql"

    def test_lookup_join_fields_not_available_before_join(self) -> None:
        rule = _sample_rule()
        rule["metadata"]["integration"] = ["endpoint"]
        rule["metadata"]["min_stack_version"] = "8.16.0"
        rule["rule"]["query"] = """
        FROM logs-endpoint.events.process-* METADATA _id, _version, _index
        | WHERE aws.cloudtrail.user_identity.type == "IAMUser"
        | LOOKUP JOIN logs-aws.cloudtrail-* ON host.name
        | KEEP host.name, aws.cloudtrail.user_identity.type, _id, _version, _index
        """
        with pytest.raises(EsqlSchemaError, match=re.escape("aws.cloudtrail.user_identity.type")):
            RuleCollection().load_dict(rule)

    def test_lookup_join_does_not_add_lookup_package_to_from_schema(self) -> None:
        """LOOKUP JOIN must not mutate metadata.integration into extra FROM packages."""
        rule = _sample_rule()
        rule["metadata"]["integration"] = ["endpoint"]
        rule["metadata"]["min_stack_version"] = "8.16.0"
        rule["rule"]["query"] = """
        FROM logs-endpoint.events.process-* METADATA _id, _version, _index
        | LOOKUP JOIN logs-aws.cloudtrail-* ON host.name
        | KEEP host.name, aws.cloudtrail.user_identity.type, _id, _version, _index
        """
        loaded = RuleCollection().load_dict(rule)
        assert loaded.contents.metadata.integration == ["endpoint"]

    def test_unknown_field_on_lookup_index_raises_schema_error(self) -> None:
        rule = _sample_rule()
        rule["metadata"]["integration"] = ["endpoint"]
        rule["metadata"]["min_stack_version"] = "8.16.0"
        rule["rule"]["query"] = """
        FROM logs-endpoint.events.process-* METADATA _id, _version, _index
        | LOOKUP JOIN logs-aws.cloudtrail-* ON host.name
        | KEEP host.name, totally.made_up.lookup_field, _id, _version, _index
        """
        with pytest.raises(EsqlSchemaError, match=re.escape("totally.made_up.lookup_field")):
            RuleCollection().load_dict(rule)

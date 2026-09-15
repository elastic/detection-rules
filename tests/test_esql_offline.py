# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Tests for offline ES|QL rule validation backed by python-esql."""

import re
import unittest
import unittest.mock
from copy import deepcopy
from types import SimpleNamespace
from typing import Any

import pytest

from detection_rules.esql import get_esql_query_event_dataset_integrations
from detection_rules.esql_errors import (
    EsqlSchemaError,
    EsqlSemanticError,
    EsqlSyntaxError,
    EsqlTypeMismatchError,
    EsqlUnknownIndexError,
)
from detection_rules.rule_loader import RuleCollection
from detection_rules.rule_validators import ESQLValidator
from detection_rules.utils import get_path, load_rule_contents

SCHEMA = {"foo": "integer", "name": "keyword", "event.category": "keyword"}


def sample_rule() -> dict[str, Any]:
    """Return a mutable production ES|QL rule fixture."""
    path = get_path(["tests", "data", "command_control_dummy_production_rule.toml"])
    return deepcopy(load_rule_contents(path)[0])


def validate_locally(rule_dict: dict[str, Any]) -> None:
    """Load a rule and run its full offline validation plan."""
    rule = RuleCollection().load_dict(rule_dict)
    validator = rule.contents.data.validator
    assert isinstance(validator, ESQLValidator)
    validator.local_validate_rule_contents(rule.contents)


def validate_text(query: str, min_stack_version: str = "9.3.0") -> Exception | None:
    """Validate a query against a fixed schema and return the mapped exception, if any."""
    error, _ = ESQLValidator(query).validate_query_text_with_schema(query, SCHEMA, "", min_stack_version)
    return error


def test_unknown_index_raises_offline() -> None:
    rule = sample_rule()
    rule["metadata"]["integration"] = ["endpoint"]
    rule["rule"]["query"] = """
    FROM logs-endpoint.fake-* METADATA _id, _version, _index
    | WHERE event.code == "malicious_file"
    | KEEP event.code, _id, _version, _index
    """
    with pytest.raises(EsqlUnknownIndexError, match=re.escape("logs-endpoint.fake")):
        validate_locally(rule)


def test_field_from_unrelated_package_raises_offline() -> None:
    rule = sample_rule()
    rule["metadata"]["integration"] = ["endpoint"]
    rule["rule"]["query"] = """
    FROM logs-endpoint.events.process-* METADATA _id, _version, _index
    | WHERE azure.signinlogs.properties.session_id == "abc"
    | KEEP azure.signinlogs.properties.session_id, _id, _version, _index
    """
    with pytest.raises(EsqlSchemaError, match=re.escape("azure.signinlogs.properties.session_id")):
        validate_locally(rule)


def test_field_outside_selected_stream_raises_offline() -> None:
    rule = sample_rule()
    rule["metadata"]["integration"] = ["aws"]
    rule["rule"]["query"] = """
    FROM logs-aws.billing-* METADATA _id, _version, _index
    | WHERE aws.cloudtrail.user_identity.type == "IAMUser"
    | KEEP aws.cloudtrail.user_identity.type, _id, _version, _index
    """
    with pytest.raises(EsqlSchemaError, match=re.escape("aws.cloudtrail.user_identity.type")):
        validate_locally(rule)


def test_dataset_extraction_uses_ast_and_normalizes_package() -> None:
    datasets = get_esql_query_event_dataset_integrations(
        'FROM logs-gcp.audit-* | WHERE event.dataset IN ("googlecloud.audit", "gcp.firewall")'
    )
    assert [(dataset.package, dataset.integration) for dataset in datasets] == [("gcp", "firewall"), ("gcp", "audit")]


def test_stack_version_feature_gate() -> None:
    """Syntax gated behind a newer stack only validates on that stack."""
    query = 'FROM logs-test-* | WHERE EQL("process where true")'
    assert isinstance(validate_text(query, "9.3.0"), EsqlSemanticError)
    assert validate_text(query, "9.4.0") is None


def test_syntax_error_is_mapped() -> None:
    assert isinstance(validate_text("FROM logs-test-* | WAT"), EsqlSyntaxError)


def test_unknown_field_is_schema_error() -> None:
    error = validate_text("FROM logs-test-* | WHERE missing_field == 1")
    assert isinstance(error, EsqlSchemaError)
    assert "missing_field" in str(error)


def test_type_mismatch_is_mapped() -> None:
    assert isinstance(validate_text("FROM logs-test-* | WHERE name > 1"), EsqlTypeMismatchError)


def test_nested_kql_is_validated() -> None:
    assert isinstance(validate_text('FROM logs-test-* | WHERE KQL("event.category : ")'), EsqlSemanticError)


def test_unique_fields_exclude_dynamic_and_metadata_columns() -> None:
    validator = ESQLValidator(
        "FROM logs-test-* METADATA _id, _version, _index"
        ' | WHERE event.category == "process"'
        " | EVAL Esql.foo_doubled = foo * 2"
        " | KEEP Esql.foo_doubled, event.category, _id, _version, _index"
    )
    assert validator.unique_fields == ["event.category", "foo"]
    assert validator.from_sources == ["logs-test-*"]
    assert validator.get_unique_field_type("Esql.foo_doubled") is not None


class TestESQLValidationPlanning(unittest.TestCase):
    """Unit tests for stack-aware offline validation planning."""

    def test_offline_validation_uses_integration_patch_floor(self) -> None:
        """Offline schemas resolve package versions at patch-adjusted stack versions."""
        query = """
        FROM logs-pkg.new_ds-* metadata _id, _version, _index
        | WHERE data_stream.dataset == "pkg.new_ds"
        | KEEP _id, _version, _index
        """
        data = SimpleNamespace(name="Test rule", rule_id="test-rule")
        metadata = SimpleNamespace(
            get_validation_stack_versions=lambda: {"9.2.0": {"ecs": "9.2.0"}, "9.3.0": {"ecs": "9.3.0"}}
        )
        resolved_stack_versions: list[str] = []

        def patch_floor_side_effect(packages, major, minor):
            self.assertIn("pkg", packages)
            return 4 if (major, minor) == (9, 2) else 0

        def compatible_version_side_effect(_package, _integration, stack_version, *_args, **_kwargs):
            resolved_stack_versions.append(str(stack_version))
            return "1.0.0", []

        validator = ESQLValidator(query)
        with (
            unittest.mock.patch(
                "detection_rules.rule_validators.TOMLRuleContents.get_packaged_integrations",
                return_value=[{"package": "pkg", "integration": "new_ds"}],
            ),
            unittest.mock.patch(
                "detection_rules.rule_validators.load_integrations_manifests",
                return_value={"pkg": {"1.0.0": {}}},
            ),
            unittest.mock.patch(
                "detection_rules.rule_validators.load_integrations_schemas",
                return_value={"pkg": {"1.0.0": {"new_ds": {"data_stream.dataset": "keyword"}}}},
            ),
            unittest.mock.patch("detection_rules.rule_validators.collect_index_field_schemas", return_value={}),
            unittest.mock.patch("detection_rules.rule_validators.prepare_mappings", return_value=({}, {}, {})),
            unittest.mock.patch("detection_rules.rule_validators.ecs.get_schema", return_value={}),
            unittest.mock.patch(
                "detection_rules.rule_validators.find_latest_integration_patch_for_minor",
                side_effect=patch_floor_side_effect,
            ),
            unittest.mock.patch(
                "detection_rules.rule_validators.find_latest_compatible_version",
                side_effect=compatible_version_side_effect,
            ),
        ):
            targets = validator.build_validation_plan(data, metadata)

        self.assertEqual(len(targets), 2)
        self.assertIn("9.2.4", resolved_stack_versions)
        self.assertIn("9.3.0", resolved_stack_versions)

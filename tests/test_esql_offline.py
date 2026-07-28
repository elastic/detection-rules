# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""End-to-end tests for offline ES|QL rule validation."""

import re
from copy import deepcopy

import pytest

from detection_rules.esql import get_esql_query_event_dataset_integrations
from detection_rules.esql_errors import EsqlSchemaError, EsqlSemanticError, EsqlUnknownIndexError
from detection_rules.rule_loader import RuleCollection
from detection_rules.rule_validators import ESQLValidator
from detection_rules.utils import get_path, load_rule_contents


def sample_rule() -> dict:
    """Return a mutable production ES|QL rule fixture."""
    path = get_path(["tests", "data", "command_control_dummy_production_rule.toml"])
    return deepcopy(load_rule_contents(path)[0])


def validate_locally(rule_dict: dict) -> None:
    """Load a rule and run its full offline schema plan."""
    rule = RuleCollection().load_dict(rule_dict)
    validator = rule.contents.data.validator
    assert isinstance(validator, ESQLValidator)
    validator.local_validate_rule_contents(rule.contents)


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
        'FROM logs-gcp.audit-* | WHERE event.dataset IN ("googlecloud.audit", "gcp.audit")'
    )
    assert [(dataset.package, dataset.integration) for dataset in datasets] == [("gcp", "audit")]


def test_stack_version_feature_gate() -> None:
    query = 'FROM logs-test-* | WHERE EQL("process where true")'
    schema = {"event.category": "keyword"}
    validator = ESQLValidator(query)

    error, _ = validator.validate_query_text_with_schema(query, schema, "", "9.3.0")
    assert isinstance(error, EsqlSemanticError)

    error, _ = validator.validate_query_text_with_schema(query, schema, "", "9.4.0")
    assert error is None

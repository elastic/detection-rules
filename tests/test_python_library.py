# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import unittest
from collections import Counter
from typing import Any, ClassVar
from unittest import mock

import eql
from marshmallow import ValidationError

from detection_rules.beats import parse_beats_from_index
from detection_rules.integrations import get_integration_schema_data, load_integrations_manifests
from detection_rules.rule import RuleMeta, TOMLRuleContents
from detection_rules.rule_loader import RuleCollection
from detection_rules.rule_validators import (
    ValidationTarget,
    group_integration_schemas_by_stack,
    group_stack_versions_by_schema,
)
from detection_rules.schemas import get_stack_schemas, load_stack_schema_map

from .base import BaseRuleTest


def mk_metadata(integrations: list[str], comments: str = "Test metadata") -> dict:
    """Create rule metadata dictionary."""
    return {
        "creation_date": "2020/12/15",
        "integration": integrations,
        "maturity": "production",
        "min_stack_comments": comments,
        "min_stack_version": "8.3.0",
        "updated_date": "2024/08/30",
    }


def mk_rule(  # noqa: PLR0913
    *,
    name: str,
    rule_id: str,
    description: str,
    risk_score: int,
    query: str,
    language: str = "eql",
    query_type: str = "eql",
    threshold: dict[str, Any] | None = None,
    alert_suppression: dict[str, Any] | None = None,
    index: list[str] | None = None,
    threat_language: str | None = None,
    threat_index: list[str] | None = None,
    threat_indicator_path: str | None = None,
    threat_mapping: list[Any] | None = None,
) -> dict[str, Any]:
    """Create rule dictionary."""
    rule = {
        "author": ["Elastic"],
        "description": description,
        "language": language,
        "name": name,
        "risk_score": risk_score,
        "rule_id": rule_id,
        "severity": "low",
        "type": query_type,
        "query": query,
        "alert_suppression": alert_suppression,
    }
    if threshold is not None:
        rule["threshold"] = threshold
    if query_type == "threat_match":
        rule["index"] = index
        rule["threat_language"] = threat_language
        rule["threat_index"] = threat_index
        rule["threat_indicator_path"] = threat_indicator_path
        rule["threat_mapping"] = threat_mapping

    return rule


class TestEQLInSet(BaseRuleTest):
    """Test EQL rule query in_set override (separate failing and passing cases)."""

    def test_eql_in_set_invalid_ip(self) -> None:
        rc = RuleCollection()
        query = """
        sequence by host.id, process.entity_id with maxspan = 5s
        [network where destination.ip in ("127.0.0.1", "::1")]
        """
        rule_dict = {
            "metadata": mk_metadata(
                ["endpoint", "windows"], comments="New fields added: required_fields, related_integrations, setup"
            ),
            "rule": mk_rule(
                name="Fake Test Rule",
                rule_id="4fffae5d-8b7d-4e48-88b1-979ed42fd9a3",
                description="Test Rule.",
                risk_score=47,
                query=query,
            ),
        }
        with self.assertRaisesRegex(eql.EqlTypeMismatchError, r"Unable to compare ip to string"):
            rc.load_dict(rule_dict)

    def test_eql_in_set_valid_address(self) -> None:
        rc = RuleCollection()
        query = """
        sequence by host.id, process.entity_id with maxspan = 10s
        [network where destination.address in ("192.168.1.1", "::1")]
        """
        rule_dict = {
            "metadata": mk_metadata(
                ["endpoint", "windows"], comments="New fields added: required_fields, related_integrations, setup"
            ),
            "rule": mk_rule(
                name="Fake Test Rule",
                rule_id="4fffae5d-8b7d-4e48-88b1-979ed42fd9a3",
                description="Test Rule.",
                risk_score=47,
                query=query,
            ),
        }
        rc.load_dict(rule_dict)


class TestEQLSequencePerIntegration(BaseRuleTest):
    """Tests for per-subquery EQL validation against the correct integration.package schema."""

    def test_sequence_valid_per_package(self) -> None:
        """Test that a sequence with subquerys from different packages validates correctly."""
        rc = RuleCollection()
        query = """
        sequence with maxspan=30m
          [any where event.dataset == "azure.identity_protection"] by azure.identityprotection.properties.user_principal_name
          [any where event.dataset == "azure.auditlogs"] by azure.auditlogs.properties.initiated_by.user.userPrincipalName
        """
        rule = {
            "metadata": mk_metadata(["azure"], comments="Per-subquery integration validation"),
            "rule": mk_rule(
                name="EQL sequence per integration test",
                rule_id="1b6e2f77-8e1f-4f8d-9f72-1d8e5f3e5f11",
                description="Validate per-subquery integration.package schemas.",
                risk_score=40,
                query=query,
            ),
        }
        # Should load without error because each subquery validates against its own package schema
        rc.load_dict(rule)

    def test_sequence_invalid_join_field_wrong_package(self) -> None:
        """Test that a sequence with a join field from a different package fails validation."""
        rc = RuleCollection()
        query = """
        sequence with maxspan=30m
          [any where event.dataset == "azure.identity_protection"] by azure.identityprotection.properties.user_principal_name
          [any where event.dataset == "azure.identity_protection"] by azure.auditlogs.properties.initiated_by.user.userPrincipalName
        """
        bad_rule = {
            "metadata": mk_metadata(["azure"], comments="Per-subquery integration validation"),
            "rule": mk_rule(
                name="EQL sequence per integration test",
                rule_id="1b6e2f77-8e1f-4f8d-9f72-1d8e5f3e5f11",
                description="Validate per-subquery integration.package schemas.",
                risk_score=40,
                query=query,
            ),
        }
        # Expect failure: join field belongs to a different package than the subquery dataset
        with self.assertRaisesRegex(eql.EqlSchemaError, r"Field not recognized"):
            rc.load_dict(bad_rule)

    def test_sequence_top_level_by_and_runs_across_integrations_valid(self) -> None:
        """Sequence-level by and per-subquery runs; subqueries use different integrations and validate correctly."""
        rc = RuleCollection()
        query = """
        sequence by host.id, agent.id with maxspan=1s
          [any where event.dataset == "azure.auditlogs" and azure.auditlogs.operation_name == "Register device"] by azure.auditlogs.properties.initiated_by.user.userPrincipalName with runs=5
          [authentication where event.dataset == "okta.system" and okta.event_type == "user.mfa.okta_verify.deny_push"] by okta.actor.id
        """
        rule = {
            "metadata": mk_metadata(["azure", "okta"], comments="Top-level sequence by and runs"),
            "rule": mk_rule(
                name="EQL sequence with top-level by and runs",
                rule_id="4e5f6a99-4567-4f8d-9f72-1d8e5f3e5f15",
                description="Validate top-level sequence by and per-subquery runs across integrations.",
                risk_score=42,
                query=query,
            ),
        }
        rc.load_dict(rule)

    def test_sequence_top_level_by_and_runs_across_integrations_invalid_join(self) -> None:
        """Sequence-level by with runs; okta subquery incorrectly uses an azure join field causing validation failure."""
        rc = RuleCollection()
        query = """
        sequence by host.id, agent.id with maxspan=1s
          [any where event.dataset == "azure.auditlogs" and azure.auditlogs.operation_name == "Register device"] by azure.auditlogs.properties.initiated_by.user.userPrincipalName with runs=5
          [authentication where event.dataset == "okta.system" and okta.event_type == "user.mfa.okta_verify.deny_push"] by azure.auditlogs.properties.initiated_by.user.userPrincipalName
        """
        bad_rule = {
            "metadata": mk_metadata(["azure", "okta"], comments="Top-level sequence by and runs invalid join"),
            "rule": mk_rule(
                name="EQL sequence with top-level by and runs invalid",
                rule_id="4e5f6a99-4567-4f8d-9f72-1d8e5f3e5f16",
                description="Invalid: okta subquery uses azure join field.",
                risk_score=42,
                query=query,
            ),
        }
        with self.assertRaisesRegex(eql.EqlSchemaError, r"Field not recognized"):
            rc.load_dict(bad_rule)

    def test_sequence_okta_missing_in_metadata_but_present_in_dataset(self) -> None:
        """Okta dataset appears in a subquery but is not listed in metadata; dataset should drive schema selection."""
        rc = RuleCollection()
        query = """
        sequence with maxspan=30m
        [any where event.dataset == "azure.identity_protection"] by azure.identityprotection.properties.user_principal_name
        [any where event.dataset == "azure.auditlogs" and azure.auditlogs.operation_name == "Register device"] by azure.auditlogs.properties.initiated_by.user.userPrincipalName
        [authentication where event.dataset == "okta.system" and okta.event_type == "user.mfa.okta_verify.deny_push"] by okta.actor.id
        """
        rule = {
            # Intentionally do not include "okta" in metadata.integrations
            "metadata": mk_metadata(["azure"], comments="Okta present via dataset only"),
            "rule": mk_rule(
                name="EQL sequence with okta dataset only",
                rule_id="3c4d5e77-2345-4f8d-9f72-1d8e5f3e5f13",
                description="Validate that dataset usage includes okta schema even if not in metadata.",
                risk_score=50,
                query=query,
            ),
        }
        # Should load without error because get_packaged_integrations includes packages parsed from datasets
        rc.load_dict(rule)

    def test_sequence_across_integrations_valid(self) -> None:
        """Sequence uses azure and crowdstrike datasets; each subquery validates against its own integration."""
        rc = RuleCollection()
        query = """
        sequence with maxspan=30m
          [any where event.dataset == "azure.auditlogs"] by azure.auditlogs.properties.initiated_by.user.userPrincipalName
          [any where event.dataset == "crowdstrike.fdr"] by process.executable
        """
        rule = {
            "metadata": mk_metadata(["azure", "crowdstrike"], comments="Cross-integration per-subquery validation"),
            "rule": mk_rule(
                name="EQL sequence across integrations valid",
                rule_id="2a3b4c55-1234-4f8d-9f72-1d8e5f3e5f11",
                description="Validate sequence subquerys across azure and crowdstrike integrations.",
                risk_score=35,
                query=query,
            ),
        }
        rc.load_dict(rule)

    def test_sequence_across_integrations_invalid_crowdstrike_subquery_azure_field(self) -> None:
        """CrowdStrike subquery incorrectly uses an azure join field, which should fail validation."""
        rc = RuleCollection()
        query = """
        sequence with maxspan=30m
          [any where event.dataset == "azure.auditlogs"] by azure.auditlogs.properties.initiated_by.user.userPrincipalName
          [any where event.dataset == "crowdstrike.fdr"] by azure.auditlogs.properties.initiated_by.user.userPrincipalName
        """
        bad_rule = {
            "metadata": mk_metadata(["azure", "crowdstrike"], comments="Cross-integration per-subquery validation"),
            "rule": mk_rule(
                name="EQL sequence across integrations invalid",
                rule_id="2a3b4c55-1234-4f8d-9f72-1d8e5f3e5f12",
                description="CrowdStrike subquery incorrectly uses an azure join field.",
                risk_score=35,
                query=query,
            ),
        }
        with self.assertRaisesRegex(eql.EqlSchemaError, r"Field not recognized"):
            rc.load_dict(bad_rule)

    def test_sequence_mixed_dataset_and_datasetless_subquery_invalid_field(self) -> None:
        """First subquery has dataset; second is datasetless with an invalid vendor field; with no metadata integration
        for the datasetless subquery, integration validation so overall validation should fail.
        """
        rc = RuleCollection()
        query = """
        sequence with maxspan=30m
          [any where event.dataset == "azure.auditlogs"] by azure.auditlogs.properties.initiated_by.user.userPrincipalName
          [any where foo.invalid_field == "badfield"] by host.id
        """
        bad_rule = {
            # No integrations in metadata: datasetless subquery should not be validated against any integration
            "metadata": mk_metadata([], comments="Mixed dataset and datasetless invalid field"),
            "rule": mk_rule(
                name="EQL sequence mixed dataset and datasetless invalid",
                rule_id="5f6071aa-5678-4f8d-9f72-1d8e5f3e5f17",
                description="Second datasetless subquery contains an invalid field; expect failure.",
                risk_score=33,
                query=query,
            ),
        }
        with self.assertRaisesRegex(eql.EqlSchemaError, r"Field not recognized"):
            rc.load_dict(bad_rule)

    def test_sequence_datasetless_subquery_with_metadata_integration_valid(self) -> None:
        """Datasetless azure subquery uses azure.* fields with metadata including azure; should validate and pass."""
        rc = RuleCollection()
        query = """
        sequence with maxspan=30m
          [any where azure.identityprotection.properties.user_principal_name != null] by azure.identityprotection.properties.user_principal_name
          [any where event.dataset == "azure.auditlogs"] by azure.auditlogs.properties.initiated_by.user.userPrincipalName
        """
        rule = {
            "metadata": mk_metadata(["azure"], comments="Datasetless subquery with azure fields"),
            "rule": mk_rule(
                name="EQL sequence datasetless azure subquery",
                rule_id="3d4e5f88-3456-4f8d-9f72-1d8e5f3e5f14",
                description="Datasetless azure subquery relies on metadata/field inference for package schema.",
                risk_score=30,
                query=query,
            ),
        }
        rc.load_dict(rule)


class TestAlertSuppressionValidation(BaseRuleTest):
    """Tests for alert_suppression field validation in rules."""

    def test_threshold_rule_duration(self) -> None:
        """Test that a threshold rule with alert_suppression with just duration validates correctly."""
        rc = RuleCollection()
        query = """
        process.name: \"test\"
        """
        rule_dict: dict[str, Any] = {
            "metadata": mk_metadata(
                ["endpoint", "windows"], comments="New fields added: required_fields, related_integrations, setup"
            ),
            "rule": mk_rule(
                name="Fake Test Rule",
                rule_id="4fffae5d-8b7d-4e48-88b1-979ed42fd9a3",
                description="Test Rule.",
                risk_score=47,
                query=query,
                language="kuery",
                query_type="threshold",
                threshold={"field": [], "value": 200, "cardinality": []},
                alert_suppression={"duration": {"value": 5, "unit": "h"}},
            ),
        }
        _ = rc.load_dict(rule_dict)

    def test_query_rule_duration(self) -> None:
        """Test that a query rule with alert_suppression with group_by and missing_fields_strategy validates correctly."""
        rc = RuleCollection()
        query = """
        process.name: \"test\"
        """
        rule_dict: dict[str, Any] = {
            "metadata": mk_metadata(
                ["endpoint", "windows"], comments="New fields added: required_fields, related_integrations, setup"
            ),
            "rule": mk_rule(
                name="Fake Test Rule",
                rule_id="4fffae5d-8b7d-4e48-88b1-979ed42fd9a3",
                description="Test Rule.",
                risk_score=47,
                query=query,
                language="kuery",
                query_type="query",
                threshold=None,
                alert_suppression={"duration": {"value": 5, "unit": "h"}},
            ),
        }
        with self.assertRaises((ValidationError, TypeError)):
            _ = rc.load_dict(rule_dict)

    def test_query_rule_group_by_missing_fields(self) -> None:
        """Test that a query rule with alert_suppression with group_by and missing_fields_strategy validates correctly."""
        rc = RuleCollection()
        query = """
        process.name: \"test\"
        """
        rule_dict: dict[str, Any] = {
            "metadata": mk_metadata(
                ["endpoint", "windows"], comments="New fields added: required_fields, related_integrations, setup"
            ),
            "rule": mk_rule(
                name="Fake Test Rule",
                rule_id="4fffae5d-8b7d-4e48-88b1-979ed42fd9a3",
                description="Test Rule.",
                risk_score=47,
                query=query,
                language="kuery",
                query_type="query",
                threshold=None,
                alert_suppression={"group_by": ["process.id"], "missing_fields_strategy": "suppress"},
            ),
        }
        _ = rc.load_dict(rule_dict)

    def test_query_rule_group_by(self) -> None:
        """Test that a query rule with alert_suppression with just group_by is not valid."""
        rc = RuleCollection()
        query = """
        process.name: \"test\"
        """
        rule_dict: dict[str, Any] = {
            "metadata": mk_metadata(
                ["endpoint", "windows"], comments="New fields added: required_fields, related_integrations, setup"
            ),
            "rule": mk_rule(
                name="Fake Test Rule",
                rule_id="4fffae5d-8b7d-4e48-88b1-979ed42fd9a3",
                description="Test Rule.",
                risk_score=47,
                query=query,
                language="kuery",
                query_type="query",
                threshold=None,
                alert_suppression={"group_by": ["process.id"]},
            ),
        }
        with self.assertRaises((ValidationError, TypeError)):
            _ = rc.load_dict(rule_dict)

    def test_query_rule_missing_fields_strategy(self) -> None:
        """Test that a query rule with alert_suppression with just missing_fields_strategy is not valid."""
        rc = RuleCollection()
        query = """
        process.name: \"test\"
        """
        rule_dict: dict[str, Any] = {
            "metadata": mk_metadata(
                ["endpoint", "windows"], comments="New fields added: required_fields, related_integrations, setup"
            ),
            "rule": mk_rule(
                name="Fake Test Rule",
                rule_id="4fffae5d-8b7d-4e48-88b1-979ed42fd9a3",
                description="Test Rule.",
                risk_score=47,
                query=query,
                language="kuery",
                query_type="query",
                threshold=None,
                alert_suppression={"missing_fields_strategy": "suppress"},
            ),
        }
        with self.assertRaises((ValidationError, TypeError)):
            _ = rc.load_dict(rule_dict)

    def test_threat_match_rule(self) -> None:
        """Test that a threat_match rule with alert_suppression with all fields set is valid."""
        rc = RuleCollection()
        query = """
        process.name: \"test\"
        """
        rule_dict: dict[str, Any] = {
            "metadata": mk_metadata(
                ["endpoint", "windows"], comments="New fields added: required_fields, related_integrations, setup"
            ),
            "rule": mk_rule(
                name="Fake Test Rule",
                rule_id="4fffae5d-8b7d-4e48-88b1-979ed42fd9a3",
                description="Test Rule.",
                risk_score=47,
                query=query,
                language="kuery",
                query_type="threat_match",
                threshold=None,
                alert_suppression={
                    "group_by": ["client.ip"],
                    "duration": {"value": 12, "unit": "h"},
                    "missing_fields_strategy": "suppress",
                },
                index=["logs-*"],
                threat_language="kuery",
                threat_index=["logs-*"],
                threat_indicator_path="threat.indicator",
                threat_mapping=[{"entries": [{"field": "client.ip", "type": "mapping", "value": "client.ip"}]}],
            ),
        }
        _ = rc.load_dict(rule_dict)

    def test_threat_match_rule_missing_fields_duration(self) -> None:
        """Test that a threat_match  rule with alert_suppression with missing_fields_strategy and duration is not valid."""
        rc = RuleCollection()
        query = """
        process.name: \"test\"
        """
        rule_dict: dict[str, Any] = {
            "metadata": mk_metadata(
                ["endpoint", "windows"], comments="New fields added: required_fields, related_integrations, setup"
            ),
            "rule": mk_rule(
                name="Fake Test Rule",
                rule_id="4fffae5d-8b7d-4e48-88b1-979ed42fd9a3",
                description="Test Rule.",
                risk_score=47,
                query=query,
                language="kuery",
                query_type="threat_match",
                threshold=None,
                alert_suppression={
                    "duration": {"value": 12, "unit": "h"},
                    "missing_fields_strategy": "suppress",
                },
                index=["logs-*"],
                threat_language="kuery",
                threat_index=["logs-*"],
                threat_indicator_path="threat.indicator",
                threat_mapping=[{"entries": [{"field": "client.ip", "type": "mapping", "value": "client.ip"}]}],
            ),
        }
        with self.assertRaises((ValidationError, TypeError)):
            _ = rc.load_dict(rule_dict)


class TestValidationTargetGrouping(unittest.TestCase):
    """Test grouping of stack versions that resolve to identical validation schemas."""

    STACK_MAP: ClassVar[dict[str, dict[str, str]]] = {
        "9.6.0": {"beats": "9.5.0", "ecs": "9.5.0", "endgame": "8.4.0"},
        "9.5.0": {"beats": "9.5.0", "ecs": "9.5.0", "endgame": "8.4.0"},
        "9.4.0": {"beats": "9.4.4", "ecs": "9.4.0", "endgame": "8.4.0"},
        "8.19.0": {"beats": "8.18.3", "ecs": "8.17.0", "endgame": "8.4.0"},
    }

    def test_stack_versions_group_on_beats_and_ecs(self):
        groups = group_stack_versions_by_schema(self.STACK_MAP, "beats", "ecs")

        self.assertEqual(
            groups,
            {
                ("9.5.0", "9.5.0"): ["9.6.0", "9.5.0"],
                ("9.4.4", "9.4.0"): ["9.4.0"],
                ("8.18.3", "8.17.0"): ["8.19.0"],
            },
        )
        # first-seen order is preserved so the newest stack version reports first
        self.assertEqual(list(groups), [("9.5.0", "9.5.0"), ("9.4.4", "9.4.0"), ("8.18.3", "8.17.0")])

    def test_stack_versions_group_on_endgame_alone(self):
        groups = group_stack_versions_by_schema(self.STACK_MAP, "endgame")

        self.assertEqual(groups, {("8.4.0",): ["9.6.0", "9.5.0", "9.4.0", "8.19.0"]})

    @staticmethod
    def mk_integ(stack: str, ecs_version: str, package: str, package_version: str, schema: dict[str, str]) -> dict:
        return {
            "schema": schema,
            "package": package,
            "integration": None,
            "stack_version": stack,
            "ecs_version": ecs_version,
            "package_version": package_version,
            "endgame_version": "8.4.0",
        }

    def test_integration_schemas_merge_stacks_with_identical_resolutions(self):
        integrations = [
            self.mk_integ("9.6.0", "9.5.0", "endpoint", "9.5.0", {"process.name": "keyword"}),
            self.mk_integ("9.6.0", "9.5.0", "windows", "3.0.0", {"winlog.channel": "keyword"}),
            self.mk_integ("9.5.0", "9.5.0", "endpoint", "9.5.0", {"process.name": "keyword"}),
            self.mk_integ("9.5.0", "9.5.0", "windows", "3.0.0", {"winlog.channel": "keyword"}),
            self.mk_integ("9.4.0", "9.4.0", "endpoint", "9.4.0", {"process.name": "keyword"}),
            self.mk_integ("9.4.0", "9.4.0", "windows", "3.0.0", {"winlog.channel": "keyword"}),
        ]

        groups = group_integration_schemas_by_stack(integrations, lambda schema, _: dict(schema, prepared="keyword"))

        self.assertEqual(len(groups), 2)
        merged, single = groups
        self.assertEqual(merged.stack_versions, ["9.6.0", "9.5.0"])
        self.assertEqual(merged.ecs_version, "9.5.0")
        self.assertEqual(merged.packages, {"endpoint", "windows"})
        # union of every package schema, after preparation
        self.assertEqual(merged.schema, {"process.name": "keyword", "winlog.channel": "keyword", "prepared": "keyword"})
        self.assertEqual(single.stack_versions, ["9.4.0"])
        self.assertEqual(single.ecs_version, "9.4.0")

    def test_integration_schemas_split_when_one_package_version_differs(self):
        integrations = [
            self.mk_integ("9.6.0", "9.5.0", "endpoint", "9.6.0", {"process.name": "keyword"}),
            self.mk_integ("9.6.0", "9.5.0", "windows", "3.0.0", {"winlog.channel": "keyword"}),
            self.mk_integ("9.5.0", "9.5.0", "endpoint", "9.5.0", {"process.name": "keyword"}),
            self.mk_integ("9.5.0", "9.5.0", "windows", "3.0.0", {"winlog.channel": "keyword"}),
        ]

        groups = group_integration_schemas_by_stack(integrations, lambda schema, _: schema)

        self.assertEqual([g.stack_versions for g in groups], [["9.6.0"], ["9.5.0"]])

    def test_integration_schemas_do_not_mutate_inputs(self):
        base = {"process.name": "keyword"}
        integrations = [self.mk_integ("9.6.0", "9.5.0", "endpoint", "9.5.0", base)]

        groups = group_integration_schemas_by_stack(integrations, lambda schema, _: dict(schema, extra="keyword"))

        self.assertEqual(base, {"process.name": "keyword"})
        self.assertEqual(groups[0].schema, {"process.name": "keyword", "extra": "keyword"})


class TestValidationPlanHasNoDuplicateTargets(BaseRuleTest):
    """Test that every validation target in a rule's plan performs distinct work."""

    def test_sequence_rules_with_beats_indices_emit_each_stack_target_once(self):
        checked = 0
        for rule in self.all_rules:
            data, meta = rule.contents.data, rule.contents.metadata
            if getattr(data, "language", None) != "eql" or not getattr(data, "is_sequence", False):
                continue
            if not parse_beats_from_index(data.index_or_dataview or []):
                continue
            if meta.query_schema_validation is False:
                continue

            targets = data.validator.build_validation_plan(data, meta)
            seen = {(t.query_text, t.kind, type(t.schema).__name__, t.err_trailer) for t in targets}
            self.assertEqual(len(seen), len(targets), f"{rule.id} emits duplicate validation targets")
            checked += 1

        self.assertGreater(checked, 0, "expected at least one sequence rule with beats indices")


def _target_fields(target: ValidationTarget) -> dict[str, Any]:
    """Return the field map a target's schema validates against."""
    schema: Any = target.schema
    return schema if isinstance(schema, dict) else getattr(schema, "kql_schema", None) or schema.endgame_schema


def _target_identity(target: ValidationTarget) -> tuple[Any, ...]:
    """Return what a target validates, minus the schema contents."""
    return (
        target.kind,
        target.query_text,
        type(target.schema).__name__,
        tuple(target.beat_types or ()),
        tuple(target.integration_types or ()),
    )


def _target_signature(target: ValidationTarget) -> tuple[Any, ...]:
    """Return everything that determines how a target validates, including the full field map."""
    return (*_target_identity(target), tuple(sorted(_target_fields(target).items())))


def _describe_schema_mismatch(alone: list[ValidationTarget], grouped: list[ValidationTarget]) -> str:
    """Explain how the single-stack targets differ from the grouped targets covering that stack."""
    by_identity_alone = {_target_identity(t): t for t in alone}
    by_identity_grouped = {_target_identity(t): t for t in grouped}
    lines: list[str] = []
    for identity in set(by_identity_alone) ^ set(by_identity_grouped):
        side = "only when planned alone" if identity in by_identity_alone else "only in the grouped plan"
        lines.append(f"target {identity[0]}/{identity[2]} present {side}")
    for identity in set(by_identity_alone) & set(by_identity_grouped):
        alone_fields = _target_fields(by_identity_alone[identity])
        grouped_fields = _target_fields(by_identity_grouped[identity])
        differing = sorted(
            f for f in set(alone_fields) | set(grouped_fields) if alone_fields.get(f) != grouped_fields.get(f)
        )
        if differing:
            shown = ", ".join(differing[:10]) + (" ..." if len(differing) > 10 else "")
            lines.append(f"target {identity[0]}/{identity[2]}: {len(differing)} field(s) differ: {shown}")
    return "; ".join(lines) or "duplicate targets differ in count"


class TestValidationPlanGroupingIsLossless(BaseRuleTest):
    """Test that grouping stack versions never changes what a stack version is validated against."""

    # The grouping keys are only correct while they capture every stack-dependent input to schema assembly. Rather
    # than trust the key, rebuild each sampled plan one stack version at a time and compare against the grouped plan,
    # so a new stack-dependent input missing from the key fails here instead of silently under-validating.
    SAMPLE_PER_SHAPE = 3

    def _sample_rules(self) -> list[Any]:
        shapes: dict[str, Any] = {
            "kql with integrations": lambda d, m: d.language == "kuery" and bool(m.get("integration")),
            "kql stack only": lambda d, m: d.language == "kuery" and not m.get("integration"),
            "eql endgame": lambda d, _: d.language == "eql" and "endgame-*" in (d.index_or_dataview or []),
            "eql sequence with beats": lambda d, _: (
                d.language == "eql"
                and getattr(d, "is_sequence", False)
                and bool(parse_beats_from_index(d.index_or_dataview or []))
            ),
            "eql sequence without beats": lambda d, _: (
                d.language == "eql"
                and getattr(d, "is_sequence", False)
                and not parse_beats_from_index(d.index_or_dataview or [])
            ),
        }
        sampled: list[Any] = []
        for predicate in shapes.values():
            matches = [
                r
                for r in self.all_rules
                if getattr(r.contents.data, "language", None) in ("kuery", "eql")
                and r.contents.metadata.query_schema_validation is not False
                and predicate(r.contents.data, r.contents.metadata)
            ]
            sampled.extend(matches[: self.SAMPLE_PER_SHAPE])
        return sampled

    def test_each_stack_version_validates_against_the_same_schema_as_when_planned_alone(self):
        sampled = self._sample_rules()
        self.assertGreater(len(sampled), 0)

        for rule in sampled:
            data, meta = rule.contents.data, rule.contents.metadata
            grouped = data.validator.build_validation_plan(data, meta)
            for target in grouped:
                self.assertTrue(target.stack_versions, f"{rule.id}: target has no stack versions: {target.err_trailer}")

            for stack_version, mapping in get_stack_schemas(meta.min_stack_version).items():
                with mock.patch.object(
                    RuleMeta, "get_validation_stack_versions", return_value={stack_version: mapping}
                ):
                    alone = data.validator.build_validation_plan(data, meta)

                covering = [t for t in grouped if stack_version in (t.stack_versions or [])]
                if Counter(map(_target_signature, alone)) != Counter(map(_target_signature, covering)):
                    self.fail(
                        f"{rule.id}: stack {stack_version} is validated differently when grouped with other stacks: "
                        f"{_describe_schema_mismatch(alone, covering)}"
                    )


class TestGroupingKeyCoversResolutionInputs(BaseRuleTest):
    """Test that the inputs the grouping keys are built from have not gained new fields."""

    # A failure here means a new stack-dependent input has appeared. Decide whether it changes the schema and, if so,
    # add it to `integration_resolution_key` or `group_stack_versions_by_schema`.
    def test_integration_schema_records_have_only_known_fields(self):
        known = {
            "schema",
            "package",
            "integration",
            "stack_version",
            "ecs_version",
            "package_version",
            "endgame_version",
        }
        manifests = load_integrations_manifests()
        for rule in self.all_rules:
            data, meta = rule.contents.data, rule.contents.metadata
            if getattr(data, "language", None) not in ("kuery", "eql"):
                continue
            packaged = TOMLRuleContents.get_packaged_integrations(data, meta, manifests)
            if not packaged:
                continue
            record = next(get_integration_schema_data(data, meta, packaged), None)
            self.assertIsNotNone(record)
            self.assertEqual(set(record), known, "new field on integration schema data; is it part of the schema key?")  # type: ignore[reportArgumentType]
            return
        self.fail("expected at least one rule with packaged integrations")

    def test_stack_schema_map_entries_have_only_known_schemas(self):
        for stack_version, mapping in load_stack_schema_map().items():
            self.assertEqual(
                set(mapping), {"beats", "ecs", "endgame"}, f"{stack_version}: new schema source in stack-schema-map"
            )

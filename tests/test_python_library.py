# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from detection_rules.rule_loader import RuleCollection

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


def mk_rule(
    *,
    name: str,
    rule_id: str,
    description: str,
    risk_score: int,
    query: str,
) -> dict:
    """Create rule dictionary."""
    return {
        "author": ["Elastic"],
        "description": description,
        "language": "eql",
        "name": name,
        "risk_score": risk_score,
        "rule_id": rule_id,
        "severity": "low",
        "type": "eql",
        "query": query,
    }


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
        with self.assertRaisesRegex(ValueError, r"Error in both stack and integrations checks"):
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
        with self.assertRaisesRegex(ValueError, r"Error in both stack and integrations checks"):
            rc.load_dict(bad_rule)

    def test_sequence_okta_missing_in_metadata_but_present_in_dataset(self) -> None:
        """Okta dataset appears in a subquery but is not listed in metadata; dataset should drive schema selection."""
        rc = RuleCollection()
        query = """
        sequence with maxspan=30m
        [any where event.dataset == "azure.identity_protection"] by azure.identityprotection.properties.user_principal_name
        [any where event.dataset == "azure.auditlogs" and event.action == "Register device"] by azure.auditlogs.properties.initiated_by.user.userPrincipalName
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
        with self.assertRaisesRegex(ValueError, r"Error in both stack and integrations checks"):
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

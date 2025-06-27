# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import unittest
from copy import deepcopy

import eql.ast
import kql
from semver import Version

from detection_rules import ecs
from detection_rules.config import load_current_package_version
from detection_rules.integrations import (
    find_latest_compatible_version,
    load_integrations_manifests,
    load_integrations_schemas,
)
from detection_rules.packaging import current_stack_version
from detection_rules.rule import QueryValidator
from detection_rules.rule_loader import RuleCollection
from detection_rules.schemas import get_stack_schemas
from detection_rules.utils import get_path, load_rule_contents

from .base import BaseRuleTest

PACKAGE_STACK_VERSION = Version.parse(current_stack_version(), optional_minor_and_patch=True)


class TestEndpointQuery(BaseRuleTest):
    """Test endpoint-specific rules."""

    @unittest.skipIf(
        PACKAGE_STACK_VERSION < Version.parse("8.3.0"),
        "Test only applicable to 8.3+ stacks since query updates are min_stacked at 8.3.0",
    )
    def test_os_and_platform_in_query(self):
        """Test that all endpoint rules have an os defined and linux includes platform."""
        for rule in self.all_rules:
            if rule.contents.data.get("language") not in ("eql", "kuery"):
                continue
            if rule.path.parent.name not in ("windows", "macos", "linux"):
                # skip cross-platform for now
                continue

            ast = rule.contents.data.ast
            fields = [str(f) for f in ast if isinstance(f, (kql.ast.Field | eql.ast.Field))]

            err_msg = f"{self.rule_str(rule)} missing required field for endpoint rule"
            if "host.os.type" not in fields:
                # Exception for Forwarded Events which contain Windows-only fields.
                if rule.path.parent.name == "windows":
                    if not any(field.startswith("winlog.") for field in fields):
                        self.assertIn("host.os.type", fields, err_msg)
                else:
                    self.assertIn("host.os.type", fields, err_msg)


class TestNewTerms(BaseRuleTest):
    """Test new term rules."""

    @unittest.skipIf(
        PACKAGE_STACK_VERSION < Version.parse("8.4.0"), "Test only applicable to 8.4+ stacks for new terms feature."
    )
    def test_history_window_start(self):
        """Test new terms history window start field."""

        for rule in self.all_rules:
            if rule.contents.data.type == "new_terms":
                # validate history window start field exists and is correct
                assert rule.contents.data.new_terms.history_window_start, (
                    "new terms field found with no history_window_start field defined"
                )
                assert rule.contents.data.new_terms.history_window_start[0].field == "history_window_start", (
                    f"{rule.contents.data.new_terms.history_window_start} should be 'history_window_start'"
                )

    @unittest.skipIf(
        PACKAGE_STACK_VERSION < Version.parse("8.4.0"), "Test only applicable to 8.4+ stacks for new terms feature."
    )
    def test_new_terms_field_exists(self):
        # validate new terms and history window start fields are correct
        for rule in self.all_rules:
            if rule.contents.data.type == "new_terms":
                assert rule.contents.data.new_terms.field == "new_terms_fields", (
                    f"{rule.contents.data.new_terms.field} should be 'new_terms_fields' for new_terms rule type"
                )

    @unittest.skipIf(
        PACKAGE_STACK_VERSION < Version.parse("8.4.0"), "Test only applicable to 8.4+ stacks for new terms feature."
    )
    def test_new_terms_fields(self):
        """Test new terms fields are schema validated."""
        # ecs validation
        for rule in self.all_rules:
            if rule.contents.data.type == "new_terms":
                meta = rule.contents.metadata
                feature_min_stack = Version.parse("8.4.0")
                current_package_version = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
                min_stack_version = (
                    Version.parse(meta.get("min_stack_version")) if meta.get("min_stack_version") else None
                )
                min_stack_version = (
                    current_package_version
                    if min_stack_version is None or min_stack_version < current_package_version
                    else min_stack_version
                )

                assert min_stack_version >= feature_min_stack, (
                    f"New Terms rule types only compatible with {feature_min_stack}+"
                )
                ecs_version = get_stack_schemas()[str(min_stack_version)]["ecs"]
                beats_version = get_stack_schemas()[str(min_stack_version)]["beats"]

                # checks if new terms field(s) are in ecs, beats non-ecs or integration schemas
                queryvalidator = QueryValidator(rule.contents.data.query)
                _, _, schema = queryvalidator.get_beats_schema([], beats_version, ecs_version)
                for index_name in rule.contents.data.index:
                    schema.update(**ecs.flatten(ecs.get_index_schema(index_name)))
                integration_manifests = load_integrations_manifests()
                integration_schemas = load_integrations_schemas()
                integration_tags = meta.get("integration")
                if integration_tags:
                    for tag in integration_tags:
                        latest_tag_compat_ver, _ = find_latest_compatible_version(
                            package=tag,
                            integration="",
                            rule_stack_version=min_stack_version,
                            packages_manifest=integration_manifests,
                        )
                        if latest_tag_compat_ver:
                            integration_schema = integration_schemas[tag][latest_tag_compat_ver]
                            for policy_template in integration_schema:
                                schema.update(**integration_schemas[tag][latest_tag_compat_ver][policy_template])
                for new_terms_field in rule.contents.data.new_terms.value:
                    assert new_terms_field in schema, f"{new_terms_field} not found in ECS, Beats, or non-ecs schemas"

    @unittest.skipIf(
        PACKAGE_STACK_VERSION < Version.parse("8.4.0"), "Test only applicable to 8.4+ stacks for new terms feature."
    )
    def test_new_terms_max_limit(self):
        """Test new terms max limit."""
        # validates length of new_terms to stack version - https://github.com/elastic/kibana/issues/142862
        for rule in self.all_rules:
            if rule.contents.data.type == "new_terms":
                meta = rule.contents.metadata
                feature_min_stack = Version.parse("8.4.0")
                feature_min_stack_extended_fields = Version.parse("8.6.0")
                current_package_version = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
                min_stack_version = (
                    Version.parse(meta.get("min_stack_version")) if meta.get("min_stack_version") else None
                )
                min_stack_version = (
                    current_package_version
                    if min_stack_version is None or min_stack_version < current_package_version
                    else min_stack_version
                )
                if feature_min_stack <= min_stack_version < feature_min_stack_extended_fields:
                    assert len(rule.contents.data.new_terms.value) == 1, (
                        f"new terms have a max limit of 1 for stack versions below {feature_min_stack_extended_fields}"
                    )

    @unittest.skipIf(
        PACKAGE_STACK_VERSION < Version.parse("8.6.0"), "Test only applicable to 8.4+ stacks for new terms feature."
    )
    def test_new_terms_fields_unique(self):
        """Test new terms fields are unique."""
        # validate fields are unique
        for rule in self.all_rules:
            if rule.contents.data.type == "new_terms":
                assert len(set(rule.contents.data.new_terms.value)) == len(rule.contents.data.new_terms.value), (
                    f"new terms fields values are not unique - {rule.contents.data.new_terms.value}"
                )


class TestESQLRules(BaseRuleTest):
    """Test ESQL Rules."""

    def run_esql_test(self, esql_query, expectation, message):
        """Test that the query validation is working correctly."""
        rc = RuleCollection()
        file_path = get_path(["tests", "data", "command_control_dummy_production_rule.toml"])
        original_production_rule = load_rule_contents(file_path)

        # Test that a ValidationError is raised if the query doesn't match the schema
        production_rule = deepcopy(original_production_rule)[0]
        production_rule["rule"]["query"] = esql_query

        expectation.match_expr = message
        with expectation:
            rc.load_dict(production_rule)

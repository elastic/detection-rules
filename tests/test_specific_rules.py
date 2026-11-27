# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import unittest
from copy import deepcopy
from typing import ClassVar

import eql.ast
import kql
from semver import Version

from detection_rules import ecs
from detection_rules.config import load_current_package_version
from detection_rules.integrations import (
    find_latest_compatible_version,
    find_latest_integration_patch_for_minor,
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
                # copy: the returned schema is a memoized object shared by every caller, so updating it in place
                # would leak this rule's integration fields into later lookups (and depend on earlier ones)
                schema = dict(schema)
                for index_name in rule.contents.data.index:
                    schema.update(**ecs.flatten(ecs.get_index_schema(index_name)))
                integration_manifests = load_integrations_manifests()
                integration_schemas = load_integrations_schemas()
                integration_tags = meta.get("integration")
                if integration_tags:
                    # resolve the package like get_required_fields does: stack-schema-map keys stacks at
                    # MAJOR.MINOR.0, but a package may gate the version that adds a data stream behind a later
                    # patch (e.g. azure ~8.19.10), so resolving against the literal .0 picks an older package
                    patch_floor = find_latest_integration_patch_for_minor(
                        integration_tags, min_stack_version.major, min_stack_version.minor
                    )
                    integration_stack_version = Version(
                        min_stack_version.major,
                        min_stack_version.minor,
                        max(min_stack_version.patch, patch_floor),
                    )
                    for tag in integration_tags:
                        latest_tag_compat_ver, _ = find_latest_compatible_version(
                            package=tag,
                            integration="",
                            rule_stack_version=integration_stack_version,
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


class TestKqlQuotedWildcards(BaseRuleTest):
    """Regression tests for KQL values with wildcards that must not be quoted (issue #7214)."""

    # rule id -> field -> wildcard values that must parse as wildcards rather than literal strings
    EXPECTED_WILDCARDS: ClassVar[dict[str, dict[str, set[str]]]] = {
        "2a7823db-0bc2-48f6-aa2f-e6aef233c6dc": {
            "url.path": {
                "*splunkd/__raw/v1/postgres/recovery/*",
                "/v1/postgres/recovery/*",
                "*splunkd/__raw/v1/postgres/recovery/backup",
                "*splunkd/__raw/v1/postgres/recovery/restore",
            },
            "http.request.body.content": {
                '*"backupFile"*../*',
                '*"database"*dbname=*',
                "*/opt/splunk/var/packages/data/postgres/.pgpass*",
            },
        },
        "2635d2ba-51e7-404a-9b17-db413a1351d5": {
            "process.args": {"--dry-run*", "--help*", "-help*", "--version*"},
        },
        "77c476eb-6a49-402a-a561-267ae66daa5e": {
            "process.command_line": {"*site-packages/pip*"},
        },
        "2917d495-59bd-4250-b395-c29409b76086": {
            "process.parent.args": {"E:/wamp64/bin/apache/apache*"},
        },
    }

    @staticmethod
    def walk_ast(node):
        """Yield every KQL AST node reachable from node."""
        yield node
        slots = {slot for cls in type(node).__mro__ for slot in getattr(cls, "__slots__", ())}
        for slot in slots:
            child = getattr(node, slot, None)
            if isinstance(child, kql.ast.KqlNode):
                yield from TestKqlQuotedWildcards.walk_ast(child)
            elif isinstance(child, list):
                for item in child:
                    if isinstance(item, kql.ast.KqlNode):
                        yield from TestKqlQuotedWildcards.walk_ast(item)

    def test_wildcard_values_parse_as_wildcards(self):
        """Assert that the tuned values are parsed as wildcard nodes for their fields."""
        rules = {rule.id: rule for rule in self.all_rules}
        for rule_id, expected_fields in self.EXPECTED_WILDCARDS.items():
            with self.subTest(rule_id=rule_id):
                self.assertIn(rule_id, rules, f"rule {rule_id} not found")
                parsed = {}
                for node in self.walk_ast(rules[rule_id].contents.data.ast):
                    if isinstance(node, kql.ast.FieldComparison):
                        wildcards = {
                            child.value for child in self.walk_ast(node.value) if isinstance(child, kql.ast.Wildcard)
                        }
                        parsed.setdefault(str(node.field), set()).update(wildcards)
                for field, expected in expected_fields.items():
                    missing = expected - parsed.get(field, set())
                    self.assertFalse(missing, f"{rule_id}: {field} is missing wildcard values {sorted(missing)}")

    def test_no_quoted_wildcards(self):
        """Assert that the tuned rules have no quoted values containing a literal wildcard."""
        for rule in self.all_rules:
            if rule.id not in self.EXPECTED_WILDCARDS:
                continue
            quoted = [
                node.value
                for node in self.walk_ast(rule.contents.data.ast)
                if isinstance(node, kql.ast.String) and "*" in node.value
            ]
            self.assertEqual(quoted, [], f"{self.rule_str(rule)} has quoted wildcard values: {quoted}")


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

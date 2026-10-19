# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test ES|QL query parsing."""

import unittest

from esql.features import feature_available
from esql.versions import Version

from detection_rules.config import load_current_package_version
from detection_rules.esql import (
    get_esql_lookup_join_targets,
    get_esql_query_indices,
    get_esql_query_source_groups,
    get_esql_query_source_patterns,
    replace_esql_query_sources,
)


def _current_package() -> Version:
    return Version.parse(load_current_package_version())


def replace_with_group_position(query: str) -> str:
    """Replace each FROM clause source list with a marker for the group it belongs to."""
    groups = get_esql_query_source_groups(query)
    replacements = {span: f"test-index-{position}" for position, group in enumerate(groups) for span in group.spans}
    return replace_esql_query_sources(query, replacements)


class TestESQLQuerySources(unittest.TestCase):
    """Test extraction and replacement of the sources of an ES|QL query."""

    def test_flat_sources(self):
        """Test a query with a single FROM clause."""
        query = "FROM logs-a-*, logs-b-* METADATA _id\n| WHERE x == 1"
        self.assertListEqual(get_esql_query_indices(query), ["logs-a-*", "logs-b-*"])
        self.assertEqual(replace_with_group_position(query), "FROM test-index-0 METADATA _id\n| WHERE x == 1")

    def test_sources_without_metadata_or_pipe(self):
        """Test that a source list terminated by the end of the query is extracted."""
        self.assertListEqual(get_esql_query_indices("FROM logs-a-*"), ["logs-a-*"])
        self.assertListEqual(get_esql_query_indices("FROM logs-a-*\n| WHERE x"), ["logs-a-*"])

    def test_sources_with_and_without_trailing_dash(self):
        """Test that an index pattern is extracted whether or not a dash precedes its wildcard."""
        query = "FROM logs-azure.signinlogs*, logs-azure.auditlogs-* METADATA _id\n| WHERE x == 1"
        self.assertListEqual(get_esql_query_indices(query), ["logs-azure.signinlogs*", "logs-azure.auditlogs-*"])

    def test_cross_cluster_sources(self):
        """Test that cross cluster sources are truncated to local indices."""
        query = "FROM cluster_one:logs-a-*, logs-b-* METADATA _id\n| WHERE x"
        self.assertListEqual(get_esql_query_indices(query), ["logs-a-*", "logs-b-*"])

    def test_selector_sources(self):
        """Test that component selectors are stripped from local and cross cluster sources."""
        query = "FROM logs-a-*::failures, cluster_one:logs-b-*::data, logs-c-* METADATA _id\n| WHERE x"
        self.assertListEqual(get_esql_query_indices(query), ["logs-a-*", "logs-b-*", "logs-c-*"])
        self.assertEqual(replace_with_group_position(query), "FROM test-index-0 METADATA _id\n| WHERE x")

    def test_subqueries_are_grouped_by_their_own_sources(self):
        """Test that subqueries reading different indices are grouped and replaced separately."""
        # Grammars before 9.5 keep the inner query but drop its FROM index patterns.
        if _current_package() < Version(9, 5):
            self.skipTest("Subquery FROM index spans require the 9.5 grammar")
        query = "FROM\n(\n  FROM logs-a-* METADATA _id\n  | WHERE x\n),\n(\n  FROM logs-b-* METADATA _id\n)\n| WHERE y"
        groups = get_esql_query_source_groups(query)
        self.assertListEqual([group.indices for group in groups], [["logs-a-*"], ["logs-b-*"]])
        self.assertListEqual([len(group.spans) for group in groups], [1, 1])
        self.assertEqual(
            replace_with_group_position(query),
            "FROM\n(\n  FROM test-index-0 METADATA _id\n  | WHERE x\n),\n(\n  FROM test-index-1 METADATA _id\n)\n"
            "| WHERE y",
        )

    def test_subqueries_reading_the_same_sources_share_a_group(self):
        """Test that subqueries reading the same indices share one group, and so one set of indices."""
        if _current_package() < Version(9, 5):
            self.skipTest("Subquery FROM index spans require the 9.5 grammar")
        query = "FROM (FROM logs-a-* METADATA _id | WHERE x), (FROM logs-a-* METADATA _id | WHERE y) | WHERE z"
        groups = get_esql_query_source_groups(query)
        self.assertListEqual([group.indices for group in groups], [["logs-a-*"]])
        self.assertEqual(len(groups[0].spans), 2)
        self.assertListEqual(get_esql_query_indices(query), ["logs-a-*"])
        self.assertEqual(
            replace_with_group_position(query),
            "FROM (FROM test-index-0 METADATA _id | WHERE x), (FROM test-index-0 METADATA _id | WHERE y) | WHERE z",
        )

    def test_sources_are_not_read_from_comments(self):
        """Test that a FROM keyword or index pattern within a comment is ignored."""
        line_comment = "FROM logs-a-*\n// downloads from logs-evil-* are excluded\n| WHERE x"
        block_comment = "/*\nSelects rows from logs-evil-* only\n*/\nFROM logs-a-* METADATA _id\n| WHERE x"
        self.assertListEqual(get_esql_query_indices(line_comment), ["logs-a-*"])
        self.assertListEqual(get_esql_query_indices(block_comment), ["logs-a-*"])

    def test_sources_are_not_read_from_literals(self):
        """Test that a FROM keyword or index pattern within a string literal is ignored."""
        literal = 'FROM logs-a-*\n| WHERE msg LIKE "*copied from logs-evil-**"\n| WHERE y'
        raw_literal = 'FROM logs-a-*\n| EVAL x = REPLACE(y, """from logs-evil-*""", "")\n| WHERE z'
        self.assertListEqual(get_esql_query_indices(literal), ["logs-a-*"])
        self.assertListEqual(get_esql_query_indices(raw_literal), ["logs-a-*"])

    def test_query_without_sources(self):
        """Test that a query with no FROM clause yields no groups."""
        self.assertListEqual(get_esql_query_source_groups("| WHERE x == 1"), [])
        self.assertListEqual(get_esql_query_indices("| WHERE x == 1"), [])

    def test_lookup_join_targets_are_not_from_sources(self):
        query = "FROM logs-a-* METADATA _id\n| LOOKUP JOIN threat_list ON host.name\n| WHERE x == 1"
        self.assertListEqual(get_esql_query_indices(query), ["logs-a-*"])
        self.assertListEqual(get_esql_lookup_join_targets(query), ["threat_list"])

    def test_source_patterns_keep_cluster_prefix(self):
        """Source patterns keep the written cluster prefix alongside the local index."""
        query = "FROM remote:logs-a-*, logs-b-*, remote:logs-a-* METADATA _id\n| WHERE x == 1"
        self.assertListEqual(
            get_esql_query_source_patterns(query),
            [("remote:logs-a-*", "logs-a-*"), ("logs-b-*", "logs-b-*")],
        )
        self.assertListEqual(get_esql_query_indices(query), ["logs-a-*", "logs-b-*"])

    def test_selector_strips_to_local_index(self):
        """A ::selector suffix is not part of the local index pattern."""
        query = "FROM remote:logs-a-*::failures METADATA _id\n| WHERE x == 1"
        self.assertListEqual(
            get_esql_query_source_patterns(query),
            [("remote:logs-a-*::failures", "logs-a-*")],
        )
        self.assertListEqual(get_esql_query_indices(query), ["logs-a-*"])
        self.assertListEqual(get_esql_query_source_groups(query)[0].indices, ["logs-a-*"])

    def test_configured_parse_reads_feature_gated_sources(self):
        """Source extraction uses the current package config, including COMPLETION and nested KQL."""
        completion = """
        FROM logs-a-*
        | COMPLETION triage_result = "x" WITH { "inference_id": "model" }
        """
        nested = 'FROM logs-b-* | WHERE KQL("NOT process.name : cmd.exe")'
        self.assertListEqual(get_esql_query_indices(nested), ["logs-b-*"])
        # 8.19 accepts COMPLETION ... WITH identifier, not a map literal.
        if feature_available("completion", _current_package()):
            self.assertListEqual(get_esql_query_indices(completion), ["logs-a-*"])
            self.assertListEqual(get_esql_query_source_groups(completion)[0].indices, ["logs-a-*"])

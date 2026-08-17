# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test ES|QL query parsing."""

import unittest

from detection_rules.esql import (
    get_esql_query_indices,
    get_esql_query_source_groups,
    replace_esql_query_sources,
)


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

    def test_cross_cluster_sources(self):
        """Test that cross cluster sources are truncated to local indices."""
        query = "FROM cluster_one:logs-a-*, logs-b-* METADATA _id\n| WHERE x"
        self.assertListEqual(get_esql_query_indices(query), ["logs-a-*", "logs-b-*"])

    def test_subqueries_are_grouped_by_their_own_sources(self):
        """Test that subqueries reading different indices are grouped and replaced separately."""
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

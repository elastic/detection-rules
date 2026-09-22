# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test ES|QL query parsing."""

import unittest

from detection_rules.ecs import get_multivalued_fields
from detection_rules.esql import (
    get_esql_multivalued_field_comparisons,
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

    def test_sources_with_and_without_trailing_dash(self):
        """Test that an index pattern is extracted whether or not a dash precedes its wildcard."""
        query = "FROM logs-azure.signinlogs*, logs-azure.auditlogs-* METADATA _id\n| WHERE x == 1"
        self.assertListEqual(get_esql_query_indices(query), ["logs-azure.signinlogs*", "logs-azure.auditlogs-*"])

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


class TestESQLMultivaluedFieldComparisons(unittest.TestCase):
    """Test detection of single-valued operators applied directly to multivalued fields in ES|QL queries."""

    FIELDS = ("event.category", "event.type", "process.args")

    def test_ecs_array_fields_are_multivalued(self) -> None:
        """Test that ECS array fields are multivalued and scalar fields are not."""
        multivalued = get_multivalued_fields()
        self.assertTrue({"event.category", "event.type", "process.args"} <= multivalued)
        self.assertFalse({"event.action", "host.os.type", "process.name"} & multivalued)

    def test_direct_comparisons_are_reported(self) -> None:
        """Test that each single-valued operator on a multivalued field is reported."""
        for expression in (
            'event.category == "iam"',
            '"iam" == event.category',
            'event.type != "start"',
            "event.type < 1 OR event.type > 1 OR event.type <= 1 OR event.type >= 1",
            'event.type IN ("start", "end")',
            'event.type NOT IN ("start")',
            'event.type LIKE "sta*"',
            'event.type RLIKE "sta.*"',
            '`event.type` == "start"',
            'CASE(event.type == "start", 1, 0) == 1',
        ):
            with self.subTest(expression=expression):
                hits = get_esql_multivalued_field_comparisons(f"FROM logs-* | WHERE {expression}", self.FIELDS)
                self.assertEqual(len(hits), 1)

    def test_multivalue_aware_usage_is_not_reported(self) -> None:
        """Test that MV_ functions, null checks, MV_EXPAND, and single-valued fields are not reported."""
        for query in (
            'FROM logs-* | WHERE MV_CONTAINS(event.category, "iam")',
            'FROM logs-* | WHERE MV_FIRST(event.category) == "iam" AND "iam" == MV_FIRST(event.category)',
            "FROM logs-* | WHERE MV_COUNT(process.args) > 1 AND event.category IS NOT NULL",
            'FROM logs-* | MV_EXPAND event.category | WHERE event.category == "iam"',
            'FROM logs-* | WHERE host.os.type == "linux" AND event.action == "exec"',
            'FROM logs-* // event.category == "iam"\n| WHERE message == "event.type == start"',
        ):
            with self.subTest(query=query):
                self.assertListEqual(get_esql_multivalued_field_comparisons(query, self.FIELDS), [])

    def test_only_the_offending_fields_are_reported(self) -> None:
        """Test that only the fields compared directly are reported."""
        query = """
        FROM logs-* METADATA _id
        | MV_EXPAND event.type
        | WHERE event.type == "start" AND event.category == "process" AND MV_CONTAINS(process.args, "-d")
        """
        self.assertListEqual(get_esql_multivalued_field_comparisons(query, self.FIELDS), ["event.category"])

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test for hunt toml files."""

import unittest
from functools import lru_cache
from pathlib import Path

from hunting.definitions import HUNTING_DIR, Hunt
from hunting.markdown import load_toml
from hunting.utils import load_all_toml, load_index_file


@lru_cache
def load_all_hunts() -> list[tuple[Hunt, Path]]:
    """Glob and parse every hunting TOML file once for all tests in this module."""
    return load_all_toml(HUNTING_DIR)


class TestHunt(unittest.TestCase):
    """Test hunt toml files."""

    @classmethod
    def setUpClass(cls):
        """Load the hunt TOML files once for all tests."""
        cls.all_hunts = load_all_hunts()

    def test_toml_loading(self):
        """Test loading a hunt toml file content."""
        example_toml = """
        [hunt]
        author = "Elastic"
        description = "Detects denial of service or resource exhaustion attacks."
        integration = "aws_bedrock.invocation"
        uuid = "dc181967-c32c-46c9-b84b-ec4c8811c6a0"
        name = "Denial of Service or Resource Exhaustion Attacks Detection"
        language = "ES|QL"
        license = "Elastic License v2"
        query = ['SELECT * FROM logs']
        notes = ["High token usage can strain system resources."]
        mitre = ["AML.T0034"]
        references = ["https://www.elastic.co"]
        """
        config = load_toml(example_toml)
        self.assertEqual(config.author, "Elastic")
        self.assertEqual(config.integration, "aws_bedrock.invocation")
        self.assertEqual(config.name, "Denial of Service or Resource Exhaustion Attacks Detection")
        self.assertEqual(config.language, "ES|QL")

    def test_load_toml_files(self):
        """Test loading and validating all Hunt TOML files in the hunting directory."""

        for hunt, _ in self.all_hunts:
            self.assertTrue(hunt.author)
            self.assertTrue(hunt.description)
            self.assertTrue(hunt.integration)
            self.assertTrue(hunt.name)
            self.assertTrue(hunt.language)
            self.assertTrue(hunt.query)

    def test_markdown_existence(self):
        """Ensure each TOML file has a corresponding Markdown file in the docs directory."""
        for _, toml_file in self.all_hunts:
            expected_markdown_path = toml_file.parent.parent / "docs" / toml_file.with_suffix(".md").name

            self.assertTrue(
                expected_markdown_path.exists(),
                f"Markdown file not found for {toml_file} at expected location {expected_markdown_path}",
            )

    def test_toml_existence(self):
        """Ensure each Markdown file has a corresponding TOML file in the queries directory."""
        for markdown_file in HUNTING_DIR.rglob("*/docs/*.md"):
            expected_toml_path = markdown_file.parent.parent / "queries" / markdown_file.with_suffix(".toml").name

            self.assertTrue(
                expected_toml_path.exists(),
                f"TOML file not found for {markdown_file} at expected location {expected_toml_path}",
            )


class TestHuntEsqlValidation(unittest.TestCase):
    """Hunt ES|QL checks that do not depend on loading the full corpus."""

    def test_esql_hunt_rejects_stats_by_column_dropped_by_keep(self):
        """KEEP projection must apply to hunts (no integration schema required)."""
        with self.assertRaises(ValueError) as ctx:
            Hunt(
                author="Elastic",
                description="Projection check",
                integration=["okta"],
                uuid="00000000-0000-0000-0000-000000000000",
                name="Keep drop",
                language=["ES|QL"],
                license="Elastic License v2",
                query=[
                    """from logs-okta.system*
| keep actor
| stats c = count(*) by dropped_field
"""
                ],
            )
        self.assertIn("Unknown column", str(ctx.exception))

    def test_esql_hunt_enrich_without_with_allows_policy_fields(self):
        """ENRICH without WITH injects policy columns (KEEP then WHERE native)."""
        Hunt(
            author="Elastic",
            description="Enrich policy fields",
            integration=["endpoint"],
            uuid="00000000-0000-0000-0000-000000000001",
            name="Enrich keep",
            language=["ES|QL"],
            license="Elastic License v2",
            query=[
                """from logs-endpoint.events.library-*
| keep dll.name, host.id
| ENRICH libs-policy-defend
| where native == "yes"
"""
            ],
        )


class TestHuntIndex(unittest.TestCase):
    """Test the hunting index.yml file."""

    @classmethod
    def setUpClass(cls):
        """Load the index once for all tests."""
        cls.hunting_index = load_index_file()

    def test_mitre_techniques_present(self):
        """Ensure each query has at least one MITRE technique."""
        for queries in self.hunting_index.values():
            for query_uuid, query_data in queries.items():
                self.assertTrue(
                    query_data.get("mitre"),
                    f"No MITRE techniques found for query: {query_data.get('name', query_uuid)}",
                )

    def test_valid_structure(self):
        """Ensure each query entry has a valid structure."""
        required_fields = ["name", "path", "mitre"]

        for queries in self.hunting_index.values():
            for query_data in queries.values():
                for field in required_fields:
                    self.assertIn(field, query_data, f"Missing field '{field}' in query: {query_data}")

    def test_all_files_in_index(self):
        """Ensure all TOML files are included in the index."""
        missing_index_entries = []
        uuids = [hunt.uuid for hunt, _ in load_all_hunts()]

        for queries in self.hunting_index.values():
            missing_index_entries.extend([query_uuid for query_uuid in queries if query_uuid not in uuids])

        self.assertFalse(
            missing_index_entries, f"Missing index entries for the following queries: {missing_index_entries}"
        )


if __name__ == "__main__":
    unittest.main()

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test for hunt toml files."""
import unittest
from collections import Counter

from hunting.markdown import HUNTING_DIR, load_toml
from hunting.utils import load_index


class TestHunt(unittest.TestCase):
    """Test hunt toml files."""

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
        self.assertEqual(config.uuid, "dc181967-c32c-46c9-b84b-ec4c8811c6a0")
        self.assertEqual(
            config.name, "Denial of Service or Resource Exhaustion Attacks Detection"
        )
        self.assertEqual(config.language, "ES|QL")

    def test_load_toml_files(self):
        """Test loading and validating all Hunt TOML files in the hunting directory."""

        for toml_file in HUNTING_DIR.rglob("*.toml"):
            toml_contents = toml_file.read_text()
            hunt = load_toml(toml_contents)
            self.assertTrue(hunt.author)
            self.assertTrue(hunt.description)
            self.assertTrue(hunt.integration)
            self.assertTrue(hunt.uuid)
            self.assertTrue(hunt.name)
            self.assertTrue(hunt.language)
            self.assertTrue(hunt.query)

    def test_markdown_existence(self):
        """Ensure each TOML file has a corresponding Markdown file in the docs directory."""
        for toml_file in HUNTING_DIR.rglob("*.toml"):
            expected_markdown_path = (
                toml_file.parent.parent / "docs" / toml_file.with_suffix(".md").name
            )

            self.assertTrue(
                expected_markdown_path.exists(),
                f"Markdown file not found for {toml_file} at expected location {expected_markdown_path}",
            )


class TestHuntIndex(unittest.TestCase):
    """Test the hunting index.yml file."""
    @classmethod
    def setUpClass(cls):
        """Load the index once for all tests."""
        cls.hunting_index = load_index()

    def test_unique_uuid(self):
        """Ensure each hunt has a unique UUID."""
        uuids = []

        # Collect all UUIDs from the index
        for folder, queries in self.hunting_index.items():
            for query in queries:
                uuids.append(query['uuid'])

        # Count occurrences of each UUID
        uuid_counts = Counter(uuids)

        # Find any duplicates
        duplicates = [uuid for uuid, count in uuid_counts.items() if count > 1]

        # Assert that there are no duplicates
        self.assertEqual(len(duplicates), 0, f"Duplicate UUIDs found: {duplicates}")

    def test_mitre_techniques_present(self):
        """Ensure each query has at least one MITRE technique."""

        for folder, queries in self.hunting_index.items():
            for query in queries:
                self.assertTrue(query['mitre'], f"No MITRE techniques found for query: {query['name']}")

    def test_valid_structure(self):
        """Ensure each query entry has a valid structure."""
        required_fields = ['name', 'path', 'uuid', 'mitre']

        for folder, queries in self.hunting_index.items():
            for query in queries:
                for field in required_fields:
                    self.assertIn(field, query, f"Missing field '{field}' in query: {query}")


if __name__ == "__main__":
    unittest.main()

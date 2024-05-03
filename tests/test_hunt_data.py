# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test for hunt toml files."""
import unittest

from hunting.generate_markdown import load_toml, HUNTING_DIR


class TestHunt(unittest.TestCase):
    """Test hunt toml files."""

    def test_toml_loading(self):
        """Test loading a hunt toml file content."""
        example_toml = """
        [hunt]
        author = "Elastic"
        integration = "aws_bedrock.invocation"
        uuid = "dc181967-c32c-46c9-b84b-ec4c8811c6a0"
        name = "Denial of Service or Resource Exhaustion Attacks Detection"
        language = "ES|QL"
        query = 'SELECT * FROM logs'
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
            self.assertTrue(hunt.integration)
            self.assertTrue(hunt.uuid)
            self.assertTrue(hunt.name)
            self.assertTrue(hunt.language)
            self.assertTrue(hunt.query)


if __name__ == "__main__":
    unittest.main()

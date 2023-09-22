# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test definitions."""
import re
import unittest

from detection_rules.schemas import definitions


class TestDefinitions(unittest.TestCase):
    """Tests for formatting of definitions constants."""

    def test_wildcard_tag_validation(self):
        """Test that tags catagories that contain wildcards have valid expressions."""
        invalid = []

        # Get tags with regex definitions form definitions.EXPECTED_RULE_TAGS
        wildcard_tags = set([tag for tag in definitions.EXPECTED_RULE_TAGS if "*" in tag.split(":")[1]])
        for tag in wildcard_tags:
            try:
                re.compile(tag)
            except re.error:
                invalid.append(tag)

        if invalid:
            self.fail(f"Invalid regex in wildcard tags:\n{invalid}")
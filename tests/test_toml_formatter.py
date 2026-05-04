# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import copy
import json
import unittest
from pathlib import Path

import pytoml

from detection_rules.rule_formatter import nested_normalize, toml_write
from detection_rules.utils import get_etc_path

tmp_file = "tmp_file.toml"


class TestRuleTomlFormatter(unittest.TestCase):
    """Test that the custom toml formatting is not compromising the integrity of the data."""

    maxDiff = None

    def setUp(self):
        with get_etc_path(["test_toml.json"]).open() as f:
            self.test_data = json.load(f)

    def compare_formatted(self, data, callback=None, kwargs=None):
        """Compare formatted vs expected."""
        tmp_path = Path(tmp_file)
        try:
            toml_write(copy.deepcopy(data), tmp_path)

            formatted_data = tmp_path.read_text()
            formatted_contents = pytoml.loads(formatted_data)

            # callbacks such as nested normalize leave in line breaks, so this must be manually done
            query = data.get("rule", {}).get("query")
            if query:
                data["rule"]["query"] = query.strip()

            original = json.dumps(copy.deepcopy(data), sort_keys=True)

            if callback:
                kwargs = kwargs or {}
                formatted_contents = callback(formatted_contents, **kwargs)

            # callbacks such as nested normalize leave in line breaks, so this must be manually done
            query = formatted_contents.get("rule", {}).get("query")
            if query:
                formatted_contents["rule"]["query"] = query.strip()

            formatted = json.dumps(formatted_contents, sort_keys=True)
            self.assertEqual(original, formatted, "Formatting may be modifying contents")
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def compare_test_data(self, test_dicts, callback=None):
        """Compare test data against expected."""
        for data in test_dicts:
            self.compare_formatted(data, callback=callback)

    def test_normalization(self):
        """Test that normalization does not change the rule contents."""
        self.compare_test_data([nested_normalize(self.test_data[0])], callback=nested_normalize)

    def test_formatter_rule(self):
        """Test that formatter and encoder do not change the rule contents."""
        self.compare_test_data([self.test_data[0]])

    def test_formatter_deep(self):
        """Test that the data remains unchanged from formatting."""
        self.compare_test_data(self.test_data[1:])

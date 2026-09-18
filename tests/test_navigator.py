# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Tests for ATT&CK navigator layer generation."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from detection_rules.navigator import NavigatorBuilder, sanitize_navigator_name


class TestNavigatorNames(unittest.TestCase):
    """Ensure navigator layer filenames stay on a single path component."""

    def test_sanitize_replaces_path_separators(self) -> None:
        self.assertEqual(
            sanitize_navigator_name("tags-lnk/shortcut-abuse"),
            "tags-lnk-shortcut-abuse",
        )
        self.assertEqual(
            sanitize_navigator_name("indexes-logs-endpoint.events.*"),
            "indexes-logs-endpoint.events.WILDCARD",
        )

    def test_save_slash_tag_does_not_create_nested_directory(self) -> None:
        builder = NavigatorBuilder([])
        builder.layers["tags"]["lnk/shortcut-abuse"]["defense evasion"]["T1204"] = {
            "metadata": [{"name": "test", "value": "id"}],
            "links": [{"label": "repo", "url": "https://github.com/elastic/detection-rules"}],
        }
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            path, _built = builder.save_layer("tags", directory, layer_key="lnk/shortcut-abuse", verbose=False)
            self.assertEqual(path.parent, directory)
            self.assertEqual(path.name, "Elastic-detection-rules-tags-lnk-shortcut-abuse.json")
            self.assertTrue(path.is_file())

    def test_save_all_raises_on_sanitized_filename_collision(self) -> None:
        builder = NavigatorBuilder([])
        technique = {
            "metadata": [{"name": "test", "value": "id"}],
            "links": [{"label": "repo", "url": "https://github.com/elastic/detection-rules"}],
        }
        builder.layers["tags"]["lnk/shortcut-abuse"]["defense evasion"]["T1204"] = technique
        builder.layers["tags"]["lnk-shortcut-abuse"]["defense evasion"]["T1204"] = {
            "metadata": [{"name": "other", "value": "id2"}],
            "links": [{"label": "repo", "url": "https://github.com/elastic/detection-rules"}],
        }
        with TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError) as ctx:
                builder.save_all(Path(tmp), verbose=False)
        self.assertIn("collide after sanitization", str(ctx.exception))
        self.assertIn("lnk-shortcut-abuse.json", str(ctx.exception))

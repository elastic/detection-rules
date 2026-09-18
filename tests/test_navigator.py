# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Tests for ATT&CK navigator layer generation."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from detection_rules.attack import CURRENT_ATTACK_VERSION
from detection_rules.navigator import Navigator, NavigatorBuilder, sanitize_navigator_name


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
        built = Navigator.from_dict(
            {
                "name": "Elastic-detection-rules-tags-lnk/shortcut-abuse",
                "techniques": [],
                "versions": {"attack": CURRENT_ATTACK_VERSION},
            }
        )
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            path = NavigatorBuilder._save(built, directory, verbose=False)
            self.assertEqual(path.parent, directory)
            self.assertEqual(path.name, "Elastic-detection-rules-tags-lnk-shortcut-abuse.json")
            self.assertTrue(path.is_file())
